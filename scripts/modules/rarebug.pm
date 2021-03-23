package rarebug;

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
    my $context = $_[3];
    my $waypoints = $_[4];

    my $workspace = "$BASEWORKSPACEPATH/$experiment_name/$subject";

    my $binary_base = "$workspace/binaries";
    my $binary_dir =  "$binary_base/$context";
    my $binary_name = "rarebug";
    utils::create_binary_dir_and_backup_existing($binary_dir, $binary_name);

    my $FUZZ_FACTORY = "$TOOLS/FuzzFactory";
    my $build_command = "$FUZZ_FACTORY/afl-clang-fast -fno-inline-functions -fno-discard-value-names -fno-unroll-loops";

    my $use_asan = ($context =~ /asan/);
    if ($use_asan) {
        $ENV{"AFL_USE_ASAN"} = 1;
    }

    my $use_vvperm = ($waypoints =~ /vvperm/);
    if ($use_vvperm) {
        $build_command .= " -variables_file=$RESOURCES/rarebug_vvperm_variables_file.txt"
    }

    my $src_dir = "$SUBJECTS/rarebug";

    $build_command .= " $src_dir/rarebug.c -o $binary_dir/$binary_name";

    if ($waypoints ne "none") {
        $ENV{"WAYPOINTS"} = $waypoints;
        system $build_command;
    } else {
        system $build_command;
    }

    delete $ENV{"WAYPOINTS"};
    delete $ENV{"AFL_USE_ASAN"};
}

sub fuzz {
    my $pid = fork;
    return $pid if $pid;

    my $experiment_name = $_[0];
    my $subject = $_[1];
    my $version = $_[2];
    my $exec_context = $_[3];
    my $waypoints = $_[4];
    my $binary_context = $_[5];
    my $resume = $_[6];

    my $workspace = "$BASEWORKSPACEPATH/$experiment_name/$subject";
    my $results_base = "$workspace/results";
    my $results_dir = "$results_base/$exec_context";

    if (!$resume) {
        utils::create_results_dir_and_backup_existing($results_base, $exec_context);
    } elsif (! -d $results_dir) {
        die "Cannot resume because cannot find results dir at $results_dir";
    }

    my $binary = "$workspace/binaries/$binary_context/rarebug";
    if (! -e $binary) {
        die "Could not find binary for binary context $binary_context at $binary";
    }

    my $FUZZ_FACTORY = "$TOOLS/FuzzFactory";
    my $fuzz_command = "$FUZZ_FACTORY/afl-fuzz";
    if ($waypoints ne "none") {
        $fuzz_command .= " -p";
    }

    if ($resume) {
        $fuzz_command .= " -i-"
    } else {
        my $seeds_directory = "$RESOURCES/seeds/rarebug";
        $fuzz_command .= " -i $seeds_directory";
    }

    $fuzz_command .= " -o $results_dir -T \"rarebug-$experiment_name-$exec_context\"";

    my $use_asan = ($binary_context =~ /asan/);
    if ($use_asan) {
        $ENV{"ASAN_OPTIONS"} = "abort_on_error=1:detect_leaks=0:symbolize=0:exitcode=86:allocator_may_return_null=1";
        $fuzz_command .= " -m none";
    }

    if ($waypoints =~ /vvdump/) {
        $fuzz_command .= " -t 100";
    }

    $fuzz_command .= " $binary";

    # Need to run in shell using exec otherwise it runs it as sh -c $fuzz_command and the pid we get is of sh. So when
    # we try to kill it, it doesn't work.
    exec "exec $fuzz_command";
}

1;