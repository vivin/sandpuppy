package libpng;

use strict;
use warnings FATAL => 'all';
use Log::Simple::Color;
use File::Path qw(make_path);
use utils;

my $log = Log::Simple::Color->new;
my $BASEPATH = glob "~/Projects/phd";
my $TOOLS = "$BASEPATH/tools";
my $RESOURCES = "$BASEPATH/resources";
my $SUBJECTS = "$BASEPATH/subjects";

sub build {
    my $experiment_name = $_[0];
    my $subject = $_[1];
    my $version = $_[2];
    my $waypoints = $_[3];
    my $binary_context = $_[4];
    my $options = $_[5];

    my $libpng_src_dir = "$SUBJECTS/libpng/$version";
    my $libpng_resources = "$RESOURCES/archives/libpng";

    $log->info("Checking if source is already unpacked...");
    if (! -d $libpng_src_dir) {
        $log->info("Source is not unpacked. Unpacking...");

        my $libpng_src = "$libpng_resources/libpng-$version.tar.gz";
        if (! -f $libpng_src) {
            die "Could not find libpng source: $libpng_src";
        }

        if (! -d "$SUBJECTS/libpng") {
            system ("mkdir -p $SUBJECTS/libpng 2> /dev/null") == 0
                or die "Failed to create $SUBJECTS/libpng";
        }

        chdir "$SUBJECTS/libpng";
        system ("tar -zxvf $libpng_src");
        rename "libpng-$version", $version;

        chdir $libpng_src_dir;
        system ("patch < $libpng_resources/libpng-nocrc.patch");

    } else {
        $log->info("Source is already unpacked");
    }

    chdir $libpng_src_dir;

    if (-f "$libpng_src_dir/Makefile") {
        $log->info("Makefile exists; cleaning.");
        system ("make clean");
        system ("find . -type f -name 'config.cache' | xargs rm");
    }

    my $FUZZ_FACTORY = "$TOOLS/FuzzFactory";
    my $build_command = "$FUZZ_FACTORY/afl-clang-fast -fno-inline-functions -fno-discard-value-names -fno-unroll-loops";
    if ($options->{m32}) {
        $build_command .= " -m32";
    }

    if ($binary_context =~ /-asan/) {
        $ENV{"AFL_USE_ASAN"} = 1;
    }

    if ($waypoints ne "none") {
        $ENV{"WAYPOINTS"} = $waypoints;
    }

    my $clang_waypoint_options = utils::build_options_string($options->{clang_waypoint_options});
    system ("CC='$build_command$clang_waypoint_options' ./configure --disable-shared && make -j12");
    if ($? != 0) {
        delete $ENV{"WAYPOINTS"};
        delete $ENV{"AFL_USE_ASAN"};

        die "Make failed";
    }

    if ($waypoints eq "vvdump") {
        delete $ENV{"WAYPOINTS"};
    }

    my $workspace = utils::get_workspace($experiment_name, $subject, $version);

    my $binary_base = "$workspace/binaries";
    my $binary_dir =  "$binary_base/$binary_context";
    my $binary_name = "readpng";
    utils::create_binary_dir({
        binary_dir     => $binary_dir,
        artifact_names => [$binary_name],
        backup         => $options->{backup}
    });

    my $libpng_lib_version = $version;
    $libpng_lib_version =~ s/\.[0-9]+$//;
    $libpng_lib_version =~ s/\.//;

    my $libpng_lib_file = "$libpng_src_dir/.libs/libpng$libpng_lib_version.a";
    if (! -f $libpng_lib_file) {
        die "Could not find build libpng library at $libpng_lib_file";
    }

    if (! -f "$libpng_src_dir/contrib/libtests/readpng.c") {
        system ("cp $libpng_resources/readpng.c $libpng_src_dir/contrib/libtests");
    }

    chdir "$libpng_src_dir/contrib/libtests";

    $log->info("Building readpng..");

    system ("$build_command ./readpng.c -lm -lz $libpng_lib_file -o $binary_dir/$binary_name");
    if ($? != 0) {
        delete $ENV{"AFL_USE_ASAN"};
        delete $ENV{"WAYPOINTS"};

        die "Building readpng failed";
    }

    delete $ENV{"AFL_USE_ASAN"};
    delete $ENV{"WAYPOINTS"};
}

sub get_fuzz_command {
    my $experiment_name = $_[0];
    my $subject = $_[1];
    my $version = $_[2];
    my $waypoints = $_[3];
    my $binary_context = $_[4];
    my $exec_context = $_[5];
    my $options = $_[6];

    return utils::build_fuzz_command(
        $experiment_name,
        $subject,
        $version,
        $waypoints,
        $binary_context,
        $exec_context,
        utils::merge($options, {
            binary_name     => "readpng",
            asan_memory_limit => 20971597,
            hang_timeout    => $waypoints =~ /vvdump/ ? 300 : 0,
            no_splicing     => $waypoints =~ /vvdump/ ? 1 : 0,
            seeds_directory => "$RESOURCES/seeds/libpng",
            dictionary_file => "$RESOURCES/seeds/libpng/dictionary/png.dict"
        })
    );
}

1;