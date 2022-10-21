#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';

use lib glob "~/Projects/phd/scripts/modules";
use Data::Dumper;
use File::Path qw(make_path);
use Storable qw{lock_store lock_retrieve};
use YAML::XS;

use utils;

if (! -e -d "/mnt/vivin-nfs") {
    die "Should be run on system that has results NFS mount\n";
}

if (scalar @ARGV < 3) {
    die "Syntax:\n $0 <experiment> <subject>[:<version>] <run-name> [restart|continue]\n";
}

$SIG{TERM} = \&handle_signal;

my $BASE_PATH = glob "~/Projects/phd";
my $TOOLS = "$BASE_PATH/tools";
my $TRACEGEN_BIN_CONTEXT = "vvdump-instrumented";
my $TRACEGEN_EXEC_CONTEXT = "vvdump-tracegen";
my $SANDPUPPY_FUZZING_RUN_TIME_HOURS = 4;
my $SANDPUPPY_FUZZING_RUN_TIME_SECONDS = $SANDPUPPY_FUZZING_RUN_TIME_HOURS * 60 * 60;

my @CHILDREN = ();
my $VVDPROC_PID = 0;
my $TRACEGEN_PID = 0;

my $experiment = $ARGV[0];
my $full_subject = $ARGV[1];
my $run_name = $ARGV[2];
my $restart_continue = $ARGV[3];
my $original_subject = $full_subject;
my $subject = $full_subject;
my $version;
if ($full_subject =~ /:/) {
    ($subject, $version) = split(/:/, $full_subject);
    $full_subject =~ s/:/-/;
}

my $fuzz_config = YAML::XS::LoadFile("$BASE_PATH/resources/fuzz_config.yml");

my $SCRIPT_STATE_DIR = glob "~/.script-state/$0";
if (! -d $SCRIPT_STATE_DIR) {
    make_path $SCRIPT_STATE_DIR;
}

my $RUN_KEY = "$experiment:$full_subject:$run_name";
my $run_state = {
    iteration     => 0,
    current_phase => "initial_tracegen",
    phase_stage   => "not_started"
};

my $RUN_STATE_FILE = "$SCRIPT_STATE_DIR/$RUN_KEY.yml";
if (-e -f $RUN_STATE_FILE) {
    if (!$restart_continue) {
        my $run_state_data = Dumper(YAML::XS::LoadFile($RUN_STATE_FILE));
        die "Dynamic fuzzing run already in progress for $RUN_KEY:\n$run_state_data\nInvoke with restart or continue\n";
    }

    if ($restart_continue ne "restart" || $restart_continue ne "continue") {
        die "Invoke with either restart or continue. Uncrecognized argument: $restart_continue\n";
    }

    if ($restart_continue eq "continue") {
        $run_state = YAML::XS::LoadFile($RUN_STATE_FILE);
    }
}

sub handle_signal {
    my $signame = shift;
    print "Got $signame. Cleaning up...\n";
    clean_up_children(@CHILDREN);
    die "Dying for $signame signal";
}

sub clean_up_children {
    print "\tSending TERM to processes @_\n";
    my $count = kill 'TERM', @_;
    print "\tNumber of processes signaled: $count\n";
    waitpid $_, 0 for @_;  # blocking
}

sub update_state {
    my $hash = $_[0];
    foreach my $key(keys(%{$hash})) {
        $run_state->{$key} = $hash->{$key};
    }

    YAML::XS::DumpFile($RUN_STATE_FILE, $run_state);
}

sub initial_tracegen {
    print "Building instrumented version of $full_subject for trace generation...\n";
    system "scripts/exp.pl $experiment build $full_subject with waypoints vvdump as $TRACEGEN_BIN_CONTEXT";

    print "Fuzzing instrumented version of $full_subject for trace generation...\n";
    update_state({ phase_stage => "running" });
    system "scripts/exp.pl $experiment fuzz $full_subject with waypoints vvdump using $TRACEGEN_BIN_CONTEXT as $TRACEGEN_EXEC_CONTEXT";
    update_state({ phase_stage => "done "});
}

sub analyze_traces {
    update_state({
        current_phase => "analyze_traces",
        phase_stage   => "running"
    });
    system "python tools/analysis/analyze_vvtraces.py $experiment $full_subject $TRACEGEN_BIN_CONTEXT $TRACEGEN_EXEC_CONTEXT";
    update_state({ phase_stage  => "done" });
}

sub start_sandpuppy_fuzz {
    update_state({
        current_phase => "sandpuppy_fuzz",
        phase_stage   => "launching"
    });

    # Start up the trace processor in the background so that it can collect traces as the fuzzing run progresses, from
    # novel input that is deemed interesting.
    setup_background_trace_processing();

    my $iteration = $run_state->{iteration};

    # Next we will start the sandpuppy fuzzing run
    print "Starting SandPuppy run $run_name (iteration $iteration)...\n";
    system "scripts/exp.pl $experiment spfuzz $full_subject as $run_name-$iteration";
    chomp(my $num_pods = `pod_names | grep $experiment | grep $full_subject | grep $run_name-$iteration | wc -l`);
    print "$num_pods total pods started...\n";

    update_state({
        phase_stage => "launched",
        num_pods    => $num_pods
    });
}

sub setup_background_trace_processing {
    utils::setup_named_pipe();

    my $pid = fork;
    if (!$pid) {
        chdir "$TOOLS/vvdproc";
        system "mvn package";
        exec "java -Xms8G -Xmx16G -jar target/vvdproc.jar 2>&1 >/dev/null";
    }

    push @CHILDREN, $pid;
    $VVDPROC_PID = $pid;
}

sub wait_until_pods_are_ready {
    my $iteration = $run_state->{iteration};

    chomp(my $num_pods = `pod_names | grep $experiment | grep $full_subject | grep $run_name-$iteration | wc -l`);
    print "$num_pods total pods started...\n";

    my $num_ready_pods_command = "pod_names | grep $experiment | grep $full_subject | grep $run_name-$iteration | " .
        "xargs -I% kubectl logs % | grep \"All set\" | wc -l";
    chomp(my $num_ready_pods = `$num_ready_pods_command`);
    while ($num_ready_pods < $num_pods) {
        print "Waiting on " . ($num_pods - $num_ready_pods) . " to be ready... \r";
        sleep 1;
        chomp($num_ready_pods = `$num_ready_pods_command`);
    }

    update_state({
        phase_stage => "started",
        start_time  => time()
    });
}

sub wait_until_iteration_is_done {
    my $iteration = $run_state->{iteration};
    my $start_time = $run_state->{start_time};

    while(time() - $start_time < $SANDPUPPY_FUZZING_RUN_TIME_SECONDS) {
        sleep 5 * 60; # sleep 5 minutes

        # Let's take a look at the inputs that have been generated so far. There are a few things that we want to do:
        #  - Collect all inputs that increase coverage (we will use them as initial seeds in the next run).
        #  - Keep track of coverage over time
        #  - Generate traces from new input that we care about.
        #
        # Processing the inputs will be done on the server where the copied files are actually local instead of doing it
        # over NFS because the former way is faster.

        # TODO: invoke the script via ssh using nohup and in bg while redirecting output to a file in the results dir.
        # TODO: tail -1 every 30 seconds or so to see if line matches "Analysis done!".
        # TODO: then do the rest of the cleanup and launching new iteration etc.
        # TODO: also do the state machine like stuff or whatever to be able to resume from stopping and stuff like that
        # TODO: based on the run state.
        # TODO: also make sure you have all the binaries you need in the resources directory !!!
    }
}

sub generate_traces_from_staged_tracegen_files {
    my $iteration = $run_state->{iteration};

    my $SUBJECT_DIR = utils::get_nfs_subject_directory($experiment, $subject, $version);
    my $TRACEGEN_STAGING_DIR = "$SUBJECT_DIR/results/$run_name/tracegen-staging";

    my $TRACEGEN_ITERATION_DIR = "$SUBJECT_DIR/results/$run_name/tracegen.$iteration";
    if (! -e -d $TRACEGEN_ITERATION_DIR) {
        make_path $TRACEGEN_ITERATION_DIR;
    }

    my $WORKSPACE_SUBJECT_DIR = utils::get_subject_directory($experiment, $subject, $version);
    my $TRACEGEN_BINARY_DIR = "$WORKSPACE_SUBJECT_DIR/binaries/$TRACEGEN_BIN_CONTEXT";
    my $TRACEGEN_BINARY = "$TRACEGEN_BINARY_DIR/$fuzz_config->{$subject}->{binary_name}";
    my $TRACEGEN_BINARY_ARGUMENT_TEMPLATE = $fuzz_config->{$subject}->{argument};

    my $pid = fork;
    if (!$pid) {
        if ($TRACEGEN_PID != 0) {
            system("kill -0 $TRACEGEN_PID");
            if ($? == 0) {
                waitpid $TRACEGEN_PID, 0;
            }
        }

        $ENV{"__VVD_EXP_NAME"} = $experiment;
        $ENV{"__VVD_SUBJECT"} = $version ? "$subject-$version" : $subject;
        $ENV{"__VVD_BIN_CONTEXT"} = $TRACEGEN_BIN_CONTEXT;
        $ENV{"__VVD_EXEC_CONTEXT"} = $TRACEGEN_EXEC_CONTEXT;

        # Get the list of files in the staging directory. We will generate traces and move them one by one into the
        # directory we use for keeping track of trace-generation seeds per iteration.
        chomp(my @files = `ls -fA $TRACEGEN_STAGING_DIR`);
        foreach my $file(@files) {
            my $tracegen_command = "$TRACEGEN_BINARY $TRACEGEN_BINARY_ARGUMENT_TEMPLATE";
            $tracegen_command =~ s,\@\@,$TRACEGEN_STAGING_DIR/$file,;

            system $tracegen_command;
            system "mv $TRACEGEN_STAGING_DIR/$file $TRACEGEN_ITERATION_DIR";
        }

        exit;
    }

    push @CHILDREN, $pid;
    $TRACEGEN_PID = $pid;
}