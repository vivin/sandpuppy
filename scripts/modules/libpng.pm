package libpng;

use strict;
use warnings;
use Log::Simple::Color;
use File::Path qw(make_path);
use utils;

my $log = Log::Simple::Color->new;
my $BASEPATH = glob "~/Projects/phd";
my $BASEWORKSPACEPATH = "$BASEPATH/workspace";
my $TOOLS = "$BASEPATH/tools";
my $RESOURCES = "$BASEPATH/resources";
my $SUBJECTS = "$BASEPATH/subjects";

sub build {
    my $experiment_name = $_[0];
    my $subject = $_[1];
    my $version = $_[2];
    my $binary_context = $_[3];
    my $waypoints = $_[4];
    my $additional_clang_args = $_[5];

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
    }

    my $FUZZ_FACTORY = "$TOOLS/FuzzFactory";
    my $build_command = "$FUZZ_FACTORY/afl-clang-fast -fno-inline-functions -fno-discard-value-names -fno-unroll-loops";

    my $use_asan = ($binary_context =~ /asan/);
    if ($use_asan) {
        $ENV{"AFL_USE_ASAN"} = 1;
    }

    if ($waypoints ne "none") {
        $ENV{"WAYPOINTS"} = $waypoints;
        system ("CC=\"$build_command $additional_clang_args\" ./configure --disable-shared && make -j12");
    } else {
        system ("CC=\"$build_command\" ./configure --disable-shared && make -j12");
    }

    delete $ENV{"WAYPOINTS"};

    if ($? != 0) {
        die "Make failed";
    }

    my $workspace = "$BASEWORKSPACEPATH/$experiment_name/$subject-$version";

    my $binary_base = "$workspace/binaries";
    my $binary_dir =  "$binary_base/$binary_context";
    my $binary_name = "readpng";
    utils::create_binary_dir_and_backup_existing($binary_dir, $binary_name);

    my $libpng_lib_version = $version;
    $libpng_lib_version =~ s/\.[0-9]$//;
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
        die "Building readpng failed";
    }

    delete $ENV{"AFL_USE_ASAN"};
}

sub fuzz {
    my $experiment_name = $_[0];
    my $subject = $_[1];
    my $version = $_[2];
    my $exec_context = $_[3];
    my $waypoints = $_[4];
    my $binary_context = $_[5];
    my $options = $_[6];

    my $fuzz_command = utils::build_fuzz_command(
        $experiment_name,
        $subject,
        $version,
        $exec_context,
        $waypoints,
        $binary_context,
        {
            binary_name          => "readpng",
            resume               => $options->{resume},
            use_asan             => $binary_context =~ /asan/ ? 1 : 0,
            hang_timeout         => $waypoints =~ /vvdump/ ? 300 : 0,
            non_deterministic    => 0,
            seeds_directory      => "$RESOURCES/seeds/libpng/images",
            dictionary_file      => "$RESOURCES/seeds/libpng/dictionary/png.dict",
            binary_arguments     => 0,
            sync_directory       => $options->{sync_directory},
            parallel_fuzz_mode   => $options->{parallel_fuzz_mode}
        }
    );

    my $pid = fork;
    return $pid if $pid;

    # Need to run in shell using exec otherwise it runs it as sh -c $fuzz_command and the pid we get is of sh. So when
    # we try to kill it, it doesn't work.
    exec "exec $fuzz_command";
}

1;