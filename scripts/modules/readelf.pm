package readelf;

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

    my $binutils_src_dir = "$SUBJECTS/binutils/$version";
    my $binutils_resources = "$RESOURCES/archives/binutils";

    $log->info("Checking if source is already unpacked...");
    if (! -d $binutils_src_dir) {
        $log->info("Source is not unpacked. Unpacking...");

        my $binutils_src = "$binutils_resources/binutils-$version.tar.bz2";
        if (! -f $binutils_src) {
            die "Could not find binutils source: $binutils_src";
        }

        if (! -d "$SUBJECTS/binutils") {
            system ("mkdir -p $SUBJECTS/binutils 2> /dev/null") == 0
                or die "Failed to create $SUBJECTS/binutils";
        }
        chdir "$SUBJECTS/binutils";
        system ("tar -jxvf $binutils_src");
        rename "binutils-$version", $version;

    } else {
        $log->info("Source is already unpacked");
    }

    chdir $binutils_src_dir;

    if (-f "$binutils_src_dir/Makefile") {
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
        system ("CC=\"$build_command $additional_clang_args\" ./configure && make -j12");
    } else {
        system ("CC=\"$build_command\" ./configure && make -j12");
    }

    delete $ENV{"WAYPOINTS"};
    delete $ENV{"AFL_USE_ASAN"};

    if ($? != 0) {
        die "Make failed";
    }

    my $workspace = "$BASEWORKSPACEPATH/$experiment_name/$subject-$version";

    my $binary_base = "$workspace/binaries";
    my $binary_dir =  "$binary_base/$binary_context";
    my $binary_name = "readelf";
    utils::create_binary_dir_and_backup_existing($binary_dir, $binary_name);

    my $binutils_lib_version = $version;
    $binutils_lib_version =~ s/\.[0-9]$//;
    $binutils_lib_version =~ s/\.//;

    my $readelf_binary = "$binutils_src_dir/binutils/readelf";
    if (! -f $readelf_binary) {
        die "Could not find readelf binary at $readelf_binary";
    }

    system ("cp $readelf_binary $binary_dir/$binary_name")
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
            binary_name          => "readelf",
            resume               => $options->{resume},
            use_asan             => $binary_context =~ /asan/ ? 1 : 0,
            hang_timeout         => $waypoints =~ /vvdump/ ? 600 : 0,
            non_deterministic    => 0,
            seeds_directory      => "$RESOURCES/seeds/readelf",
            dictionary_file      => 0,
            binary_arguments     => "-a \@\@",
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
