package readelf;

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

    if ($binary_context =~ /-asan/) {
        $ENV{"AFL_USE_ASAN"} = 1;
    }

    if ($waypoints ne "none") {
        $ENV{"WAYPOINTS"} = $waypoints;
    }

    my $clang_waypoint_options = utils::build_options_string($options->{clang_waypoint_options});
    system ("CC='$build_command$clang_waypoint_options' ./configure && make -j12");
    if ($? != 0) {
        delete $ENV{"WAYPOINTS"};
        delete $ENV{"AFL_USE_ASAN"};

        die "Make failed";
    }

    delete $ENV{"WAYPOINTS"};
    delete $ENV{"AFL_USE_ASAN"};

    my $workspace = utils::get_workspace($experiment_name, $subject, $version);

    my $binary_base = "$workspace/binaries";
    my $binary_dir =  "$binary_base/$binary_context";
    my $binary_name = "readelf";
    utils::create_binary_dir({
        binary_dir     => $binary_dir,
        artifact_names => [$binary_name],
        backup         => $options->{backup}
    });

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
    my $waypoints = $_[3];
    my $binary_context = $_[4];
    my $exec_context = $_[5];
    my $options = $_[6];

    my ($fuzz_command, $ENV_VARS) = utils::build_fuzz_command(
        $experiment_name,
        $subject,
        $version,
        $waypoints,
        $binary_context,
        $exec_context,
        {
            binary_name         => "readelf",
            resume              => $options->{resume},
            use_asan            => $binary_context =~ /-asan/ ? 1 : 0,
            hang_timeout        => $waypoints =~ /vvdump/ ? 600 : 0,
            non_deterministic   => 0,
            slow_target         => 0,
            seeds_directory     => "$RESOURCES/seeds/readelf",
            dictionary_file     => 0,
            binary_arguments    => "-a \@\@",
            sync_directory_name => $options->{sync_directory_name},
            parallel_fuzz_mode  => $options->{parallel_fuzz_mode},
            fuzzer_id           => $options->{fuzzer_id}
        }
    );

    my $pid = fork;
    return $pid if $pid;

    foreach my $ENV_VAR (keys(%{$ENV_VARS})) {
        $ENV{$ENV_VAR} = $ENV_VARS->{$ENV_VAR};
    }

    if ($options->{async} || $options->{sync_directory_name}) {
        # During parallel fuzzing we will monitor these instances on our own, so redirect STDOUT and STDERR to /dev/null
        # Do the same for async fuzzing
        open STDOUT, ">",  "/dev/null" or die "$0: open: $!";
        open STDERR, ">&", \*STDOUT    or exit 1;
    }

    # Need to run in shell using exec otherwise it runs it as sh -c $fuzz_command and the pid we get is of sh. So when
    # we try to kill it, it doesn't work.
    exec "exec $fuzz_command";
}

1;
