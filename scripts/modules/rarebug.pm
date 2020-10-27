package rarebug;

use strict;
use warnings;
use Log::Simple::Color;
use File::Path qw(make_path);

my $log = Log::Simple::Color->new;
my $BASEPATH = glob "~/Projects/phd";
my $BASEWORKSPACEPATH = "$BASEPATH/workspace";
my $TOOLS = "$BASEPATH/tools";
my $RESOURCES = "$BASEPATH/resources";
my $SUBJECTS = "$RESOURCES/subjects";

sub build {
    my $experiment_name = $_[0];
    my $subject = $_[1];
    my $context = $_[2];
    my $waypoints = $_[3];

    my $workspace = "$BASEWORKSPACEPATH/$experiment_name/$subject";

    my $binary_base = "$workspace/binaries";
    my $binary_dir = "";

    if ($context eq "default") {
        my $result = `find $binary_base -type d -name "ver[0-9]" | sed -e 's,.*\\([0-9]\\+\\),\\1,' | sort -r | head -1`;
        if ($result eq "") {
            $result = -1;
        }

        my $new_version = ++$result;

        $binary_dir = "$binary_base/ver$new_version";
    } else {
        $binary_dir = "$binary_base/$context";
    }

    my $binary = "$binary_dir/rarebug";

    if (-d $binary_dir and -e $binary) {
        my $result = `find $binary_dir -type f -name "*backup[0-9]" | sed -e 's,.*\\([0-9]\\+\\),\\1,' | sort -r | head -1`;
        if ($result eq "") {
            $result = -1;
        }

        my $new_version = ++$result;

        $log->info("Backing up existing binary to backup version $new_version");
        system ("cp $binary $binary_dir/rarebug.backup$new_version");
    } elsif (! -d $binary_dir) {
        make_path($binary_dir);
    }

    my $FUZZ_FACTORY = "$TOOLS/FuzzFactory";
    my $build_command = "$FUZZ_FACTORY/afl-clang-fast -fno-inline-functions -fno-discard-value-names -fno-unroll-loops";

    my $use_asan = ($context =~ /asan/);
    if ($use_asan) {
        $build_command .= " -fsanitize=address";
    }

    my $use_trace_dir = ($waypoints =~ /trace/);
    if ($use_trace_dir) {
        $build_command .= " -trace_directory=$workspace/traces";
    }

    my $use_named_pipe = ($waypoints =~ /vardump/);
    if ($use_named_pipe) {
        # $build_command .= " -named_pipe=$NAMED_PIPE_PATH";
    }

    # TODO: have to account for WEJON instrumentation waypoint eventually... similar arg like functions file

    my $src_dir = "$SUBJECTS/rarebug";

    $build_command .= " $src_dir/rarebug.c -o $binary_dir/rarebug";

    if ($waypoints ne "none") {
        $ENV{"WAYPOINTS"} = $waypoints;
        system $build_command;
        delete $ENV{"WAYPOINTS"};
    } else {
        system $build_command;
    }
}

sub fuzz {
    my $experiment_name = $_[0];
    my $subject = $_[1];
    my $exec_context = $_[2];
    my $waypoints = $_[3];
    my $binary_context = $_[4];
    my $resume = $_[5];

    my $workspace = "$BASEWORKSPACEPATH/$experiment_name/$subject";
    my $results_base = "$workspace/results";
    my $results_dir = "$results_base/$exec_context";

    if (!$resume) {
        if (-d $results_dir) {
            my $result = `find $results_base -type d -name "*backup[0-9]" | sed -e 's,.*\\([0-9]\\+\\),\\1,' | sort -r | head -1`;
            if ($result eq "") {
                $result = -1;
            }

            my $new_version = ++$result;

            $log->info("Backing up existing results directory to backup version $new_version");
            system ("mv $results_dir $results_base/$exec_context.backup$new_version");

        }

        make_path($results_dir);
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

    my $use_trace_dir = ($waypoints =~ /trace/);
    if ($use_trace_dir) {
        $fuzz_command .= " -R $workspace/traces";
    }

    my $use_asan = ($binary_context =~ /asan/);
    if ($use_asan) {
        $ENV{"ASAN_OPTIONS"} = "abort_on_error=1:detect_leaks=0:symbolize=0:exitcode=86";
        $fuzz_command .= " -m none";
    }

    $fuzz_command .= " $binary";

    system $fuzz_command;
    if ($use_asan) {
        delete $ENV{"ASAN_OPTIONS"};
    }
}

1;