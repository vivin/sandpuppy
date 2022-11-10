#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';

use lib glob "~/Projects/phd/scripts/modules";
use Data::Dumper;
use File::Basename;
use File::Path qw(make_path);
use File::stat;
use Log::Simple::Color;
use POSIX ":sys_wait_h";
use Redis;
use Storable qw{lock_store lock_retrieve};
use YAML::XS;

use utils;

if (! -e -d "/mnt/vivin-nfs") {
    die "Should be run on system that has results NFS mount\n";
}

my $SCRIPT_NAME = basename $0;

if (scalar @ARGV < 3) {
    die "Syntax:\n $SCRIPT_NAME <experiment> <subject>[:<version>] <run-name> [restart|continue]\n";
}

$| = 1;

# Check to see if there is already a process running
chomp(my $previous_dyn_pid = `ps -u | grep -v grep | grep "$SCRIPT_NAME $ARGV[0] $ARGV[1] $ARGV[2]" | grep -v $$ | awk '{ print \$2; }'`);
if ($previous_dyn_pid) {
    die "There is already a dyn.pl process ($previous_dyn_pid) running for the provided arguments\n";
}

$SIG{INT} = \&handle_signal;
$SIG{TERM} = \&handle_signal;

my $log = Log::Simple::Color->new;
$log->color(
    mode => 'info',
    fg   => 'white',
    bg   => 'black',
    bold => 1,
);

my $BASE_PATH = glob "~/Projects/phd";
my $TOOLS = "$BASE_PATH/tools";
my $TRACEGEN_BIN_CONTEXT = "vvdump-instrumented";
my $TRACEGEN_EXEC_CONTEXT = "vvdump-tracegen";

my $state_machine = {
    "initial_tracegen,not_started" => \&initial_tracegen,
    "initial_tracegen,started"     => \&initial_tracegen,
    "initial_tracegen,finished"    => \&analyze_traces,
    "analyze_traces,started"       => \&analyze_traces,
    "analyze_traces,finished"      => \&start_sandpuppy_fuzz,
    "sandpuppy_fuzz,launching"     => \&start_sandpuppy_fuzz,
    "sandpuppy_fuzz,launched"      => \&wait_until_pods_are_ready,
    "sandpuppy_fuzz,started"       => \&wait_until_iteration_is_done,
    "sandpuppy_fuzz,finished"      => \&analyze_traces,
    "sandpuppy_fuzz,completed"     => sub {
        print "All iterations finished! Exiting...";
        exit 0;
    }
};

my @CHILDREN = ();
my $VVDPROC_PID = 0;
my $RUN_ITERATION_TRACEGEN_PIDS = {};

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

my $BASE_NFS_PATH = utils::get_base_nfs_path();
if (! -e -f "$BASE_NFS_PATH/redis-credentials") {
    die "Could not find redis credentials\n";
}

chomp(my $redis_credentials = `cat $BASE_NFS_PATH/redis-credentials`);
my $remote_redis = Redis->new(
    server   => "206.206.192.29:31111"
);

my $fuzz_config = YAML::XS::LoadFile("$BASE_PATH/resources/fuzz_config.yml");

my $SANDPUPPY_FUZZING_RUN_TIME_HOURS = $fuzz_config->{__global__}->{hours_per_iteration};
my $SANDPUPPY_FUZZING_RUN_TIME_SECONDS = $SANDPUPPY_FUZZING_RUN_TIME_HOURS * 60 * 60;

my $num_iterations = $fuzz_config->{$subject}->{num_iterations};

my $SCRIPT_STATE_DIR = glob "~/.script-state/$SCRIPT_NAME";
if (! -d $SCRIPT_STATE_DIR) {
    make_path $SCRIPT_STATE_DIR;
}

my $RUN_KEY = "$experiment:$full_subject:$run_name";
my $run_state = {
    iteration     => 0,
    current_phase => "initial_tracegen",
    phase_status   => "not_started"
};

my $RUN_STATE_FILE = "$SCRIPT_STATE_DIR/$RUN_KEY.yml";
if (-e -f $RUN_STATE_FILE) {
    if (!$restart_continue) {
        my $run_state_data = Dumper(YAML::XS::LoadFile($RUN_STATE_FILE));
        die "Dynamic fuzzing run already in progress for $RUN_KEY:\n$run_state_data\nInvoke with restart or continue\n";
    }

    if ($restart_continue ne "restart" && $restart_continue ne "continue") {
        die "Invoke with either restart or continue. Unrecognized argument: $restart_continue\n";
    }

    if ($restart_continue eq "continue") {
        $run_state = YAML::XS::LoadFile($RUN_STATE_FILE);
    }
}

$log->info("Dynamic SandPuppy Fuzzing");
$log->info("Experiment: $experiment");
$log->info("Subject: $full_subject");
$log->info("Run: $run_name");
if ($run_state->{iteration} > 0) {
    $log->info("Iteration: $run_state->{iteration}");
}
if (defined $run_state->{num_pods}) {
    $log->info("Pods started: $run_state->{num_pods}");
}

while(1) {
    $log->info("Phase: $run_state->{current_phase} ($run_state->{phase_status})");
    $state_machine->{"$run_state->{current_phase},$run_state->{phase_status}"}->();
}

exit 0;

sub handle_signal {
    my $signame = shift;
    print "Got $signame. Cleaning up...\n";
    shutdown_background_trace_processing();
    shutdown_remote_background_results_analysis_producer();
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
    if ($run_state->{phase_status} eq "started") {
        my $choice;
        do {
            print "\nAn initial trace-generation process was interrupted. Do you want me to:\n";
            print "  a) Continue on to analyzing the traces.\n";
            print "  b) Clean up existing traces and restart trace-generation.\n";
            print "  c) Clean up existing traces and quit.\n";
            print "  d) Quit.\n\n";
            print "Enter your choice: ";

            chomp($choice = <STDIN>);
        } while (!grep /^$choice$/, ("a", "b", "c", "d"));

        exit if $choice eq "d"; # Quit; option d chosen.

        if ($choice eq "a") {
            update_state({ phase_status => "finished" });
            return;
        }

        # Options b and c both involve cleaning up the traces first.
        system "python tools/analysis/clean_redis_subject_data.py $experiment $full_subject $TRACEGEN_BIN_CONTEXT";
        exit if $choice eq "c"; # Quit after cleaning traces; option c chosen.
    } else {
        print "Building instrumented version of $full_subject for trace generation...\n";
        system "scripts/exp.pl $experiment build $full_subject with waypoints vvdump as $TRACEGEN_BIN_CONTEXT";
    }

    # Option b also ends up here because we restart trace generation after cleaning up existing traces
    print "Fuzzing instrumented version of $full_subject for trace generation...\n";
    update_state({ phase_status => "started" });

    system "scripts/exp.pl $experiment fuzz $full_subject with waypoints vvdump using $TRACEGEN_BIN_CONTEXT as $TRACEGEN_EXEC_CONTEXT";
    if ($? != 0) {
        die "Trace-generation fuzzing run failed: $!\n";
    }

    update_state({ phase_status => "finished" });
}

sub analyze_traces {
    update_state({
        current_phase => "analyze_traces",
        phase_status   => "started"
    });

    my $iteration = $run_state->{iteration};
    if ($iteration > 0) {
        my $suffix = ($iteration > 1) ? "$run_name-${\($iteration - 1)}" : "$run_name-initial_tracegen";

        print "Backing up previous trace-analysis results...\n";
        my $SUBJECT_PATH = utils::get_subject_directory($experiment, $subject, $version);
        system "mv $SUBJECT_PATH/results/$TRACEGEN_EXEC_CONTEXT $SUBJECT_PATH/results/$TRACEGEN_BIN_CONTEXT.$suffix";
        system "mv $SUBJECT_PATH/results/sandpuppy_interesting_variables.yml $SUBJECT_PATH/results/sandpuppy_interesting_variables.yml.$suffix";
        system "mv $SUBJECT_PATH/results/sandpuppy-target-name-to-id.yml $SUBJECT_PATH/results/sandpuppy-target-name-to-id.yml.$suffix";
        system "mv $SUBJECT_PATH/results/sandpuppy-vvmax-variables.txt $SUBJECT_PATH/results/sandpuppy-vvmax-variables.txt.$suffix";
        system "mkdir $SUBJECT_PATH/results/$TRACEGEN_EXEC_CONTEXT";

        print "Analyzing traces for run $run_name, iteration $iteration...\n";
    } else {
        print "Analyzing traces after initial trace-gathering run for $run_name...\n";
    }

    system "python tools/analysis/analyze_vvtraces.py $experiment $full_subject $TRACEGEN_BIN_CONTEXT $TRACEGEN_EXEC_CONTEXT";
    if ($? != 0) {
        die "Trace analysis exited with an error: $!\n";
    }

    # The trace-analysis phase is the terminal phase since it is the last thing we do after an iteration of a sandpuppy
    # run. If we are at the final iteration, update the state to reflect it. Otherwise simply mark the analysis phase
    # as done and we will automatically proceed to the next iteration of the sandpuppy fuzzing run.
    if ($iteration + 1 > $num_iterations) {
        update_state({
            current_phase => "sandpuppy_fuzz",
            phase_status   => "completed"
        });
    } else {
        update_state({
            phase_status => "finished",
            iteration   => $iteration + 1
        });
    }
}

sub start_sandpuppy_fuzz {
    update_state({
        current_phase => "sandpuppy_fuzz",
        phase_status   => "launching"
    });

    my $iteration = $run_state->{iteration};

    setup_analysis_consumer_pods_if_necessary();

    # Next we will start the sandpuppy fuzzing run
    print "Starting SandPuppy run $run_name (iteration $iteration)...\n";
    system "scripts/exp.pl $experiment spfuzz $full_subject as $run_name-$iteration";
    if ($? != 0) {
        die "Starting SandPuppy run failed: $!\n";
    }

    chomp(my $num_pods = `pod_names | grep $experiment | grep $full_subject | grep $run_name-$iteration | wc -l`);
    print "$num_pods total pods started...\n";

    update_state({
        phase_status => "launched",
        num_pods    => $num_pods
    });
}

sub wait_until_pods_are_ready {
    my $iteration = $run_state->{iteration};
    my $num_pods = $run_state->{num_pods};

    my $num_ready_pods_command = "pod_names | grep $experiment | grep $full_subject | grep $run_name-$iteration | " .
        "xargs -I% kubectl logs % | grep \"All set\" | wc -l";
    chomp(my $num_ready_pods = `$num_ready_pods_command`);
    while ($num_ready_pods < $num_pods) {
        print "Waiting on " . ($num_pods - $num_ready_pods) . " to be ready... \r";
        sleep 1;
        chomp($num_ready_pods = `$num_ready_pods_command`);
    }

    update_state({
        phase_status => "started",
        start_time  => time()
    });
}

sub wait_until_iteration_is_done {
    my $iteration = $run_state->{iteration};
    my $start_time = $run_state->{start_time};

    # Start up the trace processor in the background so that it can collect traces as the fuzzing run progresses, from
    # novel input that is deemed interesting. Also start up the analyze_result.pl script remotely in the background.
    # This script goes through all inputs that have been generated so far and:
    #  - Collects all inputs that increase coverage (we will use them as initial seeds in the next run).
    #  - Keeps track of coverage over time
    setup_background_trace_processing();
    setup_remote_background_results_analysis_producer();

    my $last_processed_files = 0;
    my $last_retrieved_processed_files_time = time();
    my $last_generated_traces_time = time();
    while(time() - $start_time < $SANDPUPPY_FUZZING_RUN_TIME_SECONDS) {
        sleep 5; # check every minute

        my $elapsed_time = time() - $start_time;
        my $remaining_time = $SANDPUPPY_FUZZING_RUN_TIME_SECONDS - $elapsed_time;

        if (time() - $last_generated_traces_time >= 60) {
            # Generate traces from tracegen files (if any)
            generate_traces_from_staged_tracegen_files();
            $last_generated_traces_time = time();
        }

        my $total_files = $remote_redis->get("$experiment:$full_subject:$run_name-$iteration.total_files");
        my $processed_files = $remote_redis->get("$experiment:$full_subject:$run_name-$iteration.processed_files");
        my $seconds_since_last_retrieved_processed_files = time() - $last_retrieved_processed_files_time;
        $last_retrieved_processed_files_time = time();
        if (defined $total_files) {
            if (!defined $processed_files) {
                print "no processed files defined\n";
                $processed_files = 0;
            }

            my $throughput = sprintf("%.2f", (($processed_files - $last_processed_files) / $seconds_since_last_retrieved_processed_files));
            my $remaining_files = $total_files - $processed_files;
            print "${remaining_time}s remaining. $processed_files processed. $remaining_files remaining to be processed. $total_files files total. ($throughput files/s)\r";

            $last_processed_files = $processed_files;
        } else {
            print "${remaining_time}s remaining.\r"
        }

        # TODO: would be nice to keep an eye on the status of pods and then resume them if they disappear or stop

        # If any analysis pods went down, start them up
        setup_analysis_consumer_pods_if_necessary();
    }

    print "\nIteration $iteration has ended. Stopping pods...\n";
    system "pod_names | grep $experiment | grep $full_subject | grep $run_name-$iteration | xargs kubectl delete pod";

    print "Sleeping for a minute so that files are old enough for results-analysis to process...\n";
    my $time = 60;
    do {
        sleep 1;
        $time--;
        print "$time seconds remaining...\r";
    } until ($time == 0);

    print "\nShutting down remote background results-analysis and waiting for it to complete...\n";
    shutdown_remote_background_results_analysis_producer();
    monitor_remote_background_results_analysis_until_done();

    print "Generating traces from remaining seeds if any...\n";
    generate_traces_from_staged_tracegen_files();
    waitpid $RUN_ITERATION_TRACEGEN_PIDS->{"$run_name-$iteration"}, 0;

    update_state({
        phase_status => "finished",
        end_time  => time()
    });
}

sub setup_analysis_consumer_pods_if_necessary {
    my $NUM_CONSUMERS = $fuzz_config->{__global__}->{num_consumers};

    chomp(my @errored_pods = `kubectl get pods | grep "sandpuppy-analysis-consumer" | grep Error | awk '{ print \$1; }'`);
    system "kubectl delete pod $_" for @errored_pods;

    my $consumers_created = 0;
    chomp(my @pods = `pod_names | grep "sandpuppy-analysis-consumer"`);
    foreach my $consumer(1..$NUM_CONSUMERS) {
        my $consumer_name = "sandpuppy-analysis-consumer-$consumer";
        if(! grep /^$consumer_name$/, @pods) {
            if ($consumers_created == 0) {
                print "\n";
            }

            system "kuboid/scripts/pod_create -c 250m -C 4000m -n $consumer_name -i vivin/sandpuppy-analysis " .
                "/home/vivin/Projects/phd/scripts/result_analysis_consumer.pl sandpuppy-analysis-channel";
            $consumers_created++;
        }
    }

    if ($consumers_created > 0) {
        my $existing_pods = scalar @pods;
        my $running_pods = 0;
        do {
            chomp($running_pods = `kubectl get pods | grep "sandpuppy-analysis-consumer" | grep Running | wc -l`);
            print "Waiting on ${\($existing_pods + $consumers_created - $running_pods)} to be ready...\r";
            sleep 1;

            # Restart error pods if any
            chomp(@errored_pods = `kubectl get pods | grep "sandpuppy-analysis-consumer" | grep Error | awk '{ print \$1; }'`);
            foreach my $errored_pod(@errored_pods) {
                my $consumer = $errored_pod;
                $consumer =~ s/sandpuppy-analysis-consumer-//;

                system "kubectl delete pod $errored_pod";
                system "kuboid/scripts/pod_create -n $errored_pod -i vivin/sandpuppy-analysis " .
                    "/home/vivin/Projects/phd/scripts/result_analysis_consumer.pl analysis.channel.$consumer";
            }
        } until($running_pods == $existing_pods + $consumers_created);
        print "\n";
    }
}

sub shutdown_analysis_consumer_pods {
    system  "pod_names | grep sandpuppy-analysis-consumer | xargs kubectl delete pod"
}

sub setup_background_trace_processing {
    return if $VVDPROC_PID; # If it is already running, exit

    utils::setup_named_pipe();

    my $pid = fork;
    if (!$pid) {
        chdir "$TOOLS/vvdproc";
        system "mvn package 2>&1 >/dev/null";
        exec "unbuffer java -Xms8G -Xmx16G -jar target/vvdproc.jar 2>&1 >/dev/null";
    }

    push @CHILDREN, $pid;
    $VVDPROC_PID = $pid;
}

sub shutdown_background_trace_processing {
    return if !$VVDPROC_PID;

    open PIPE, ">", utils::get_named_pipe_path();
    print PIPE "__\$VVDUMP_END\$__\n";
    close PIPE;
}

sub setup_remote_background_results_analysis_producer {
    my $iteration = $run_state->{iteration};

    my $NFS_SUBJECT_DIR = utils::get_nfs_subject_directory($experiment, $subject, $version);
    my $NFS_RESULTS_DIR = "$NFS_SUBJECT_DIR/results/$run_name-$iteration";

    if (-e "$NFS_RESULTS_DIR/shutdown_analyze_results") {
        system "rm $NFS_RESULTS_DIR/shutdown_analyze_results";
    }

    system "ssh -o StrictHostKeyChecking=no -i /mnt/vivin-nfs/vivin/sandpuppy-pod-key vivin\@vivin.is-a-geek.net " .
        "\"/home/vivin/Projects/phd/scripts/bg_analyze_results.sh $experiment $full_subject $run_name $iteration\"";
}

sub shutdown_remote_background_results_analysis_producer {
    my $iteration = $run_state->{iteration};

    my $NFS_SUBJECT_DIR = utils::get_nfs_subject_directory($experiment, $subject, $version);
    my $NFS_RESULTS_DIR = "$NFS_SUBJECT_DIR/results/$run_name-$iteration";
    if (! -e -d $NFS_RESULTS_DIR) {
        return;
    }

    system "touch $NFS_RESULTS_DIR/shutdown_analyze_results";
    until (-e -f "$NFS_RESULTS_DIR/shutdown_analyze_results") {
        print "Waiting for remote background results analysis to shutdown...\n";
        sleep 1;
    }
    print "Remote background results analysis is shutting down...\n";
}

sub monitor_remote_background_results_analysis_until_done {
    my $iteration = $run_state->{iteration};

    my $remaining_files;
    do {
        my $total_files = $remote_redis->get("$experiment:$full_subject:$run_name-$iteration.total_files");
        my $processed_files = $remote_redis->get("$experiment:$full_subject:$run_name-$iteration.processed_files");
        $remaining_files = $total_files - $processed_files;

        print "$total_files files total. $remaining_files remaining to be processed.\r";
        sleep 1;

        # Sometimes these guys go down. Bring them back up if necessary.
        setup_analysis_consumer_pods_if_necessary();
    } until ($remaining_files == 0);

    print "\n";

    my $NFS_SUBJECT_DIR = utils::get_nfs_subject_directory($experiment, $subject, $version);
    my $NFS_RESULTS_DIR = "$NFS_SUBJECT_DIR/results/$run_name-$iteration";

    my $ANALYZE_RESULTS_LOG_FILENAME = "analyze_results.log";
    system "rm $NFS_RESULTS_DIR/$ANALYZE_RESULTS_LOG_FILENAME";
}

sub generate_traces_from_staged_tracegen_files {
    my $wait_for_existing = $_[0];
    my $iteration = $run_state->{iteration};

    my $tracegen_pid = $RUN_ITERATION_TRACEGEN_PIDS->{"$run_name-$iteration"};
    if (defined $tracegen_pid && kill 0, $tracegen_pid) {
        if (!defined $wait_for_existing && !waitpid $tracegen_pid, WNOHANG) {
            print "Tracegen (pid: $tracegen_pid) is already running for $run_name-$iteration\n";
            return;
        }

        my $start = time();
        while (kill 0, $tracegen_pid) {
            print "Waiting for existing tracgen (pid: $tracegen_pid) to finish (${\(time() - $start)}s elapsed)...\r";
            sleep 1;
        }
    }

    my $SUBJECT_DIR = utils::get_nfs_subject_directory($experiment, $subject, $version);
    my $TRACEGEN_STAGING_DIR = "$SUBJECT_DIR/results/$run_name-$iteration/tracegen-staging";
    return if ! -e -d $TRACEGEN_STAGING_DIR;

    my $TRACEGEN_ITERATION_DIR = "$SUBJECT_DIR/results/$run_name-$iteration/tracegen";
    if (! -e -d $TRACEGEN_ITERATION_DIR) {
        make_path $TRACEGEN_ITERATION_DIR;
    }

    my $WORKSPACE_SUBJECT_DIR = utils::get_subject_directory($experiment, $subject, $version);
    my $TRACEGEN_BINARY_DIR = "$WORKSPACE_SUBJECT_DIR/binaries/$TRACEGEN_BIN_CONTEXT";
    my $TRACEGEN_BINARY = "$TRACEGEN_BINARY_DIR/$fuzz_config->{$subject}->{binary_name}";
    my $TRACEGEN_BINARY_ARGUMENT_TEMPLATE = $fuzz_config->{$subject}->{argument};

    my $pid = fork;
    if (!$pid) {
        $ENV{"__VVD_EXP_NAME"} = $experiment;
        $ENV{"__VVD_SUBJECT"} = $version ? "$subject-$version" : $subject;
        $ENV{"__VVD_BIN_CONTEXT"} = $TRACEGEN_BIN_CONTEXT;
        $ENV{"__VVD_EXEC_CONTEXT"} = $TRACEGEN_EXEC_CONTEXT;

        # Get the list of files in the staging directory. We will generate traces and move them one by one into the
        # directory we use for keeping track of trace-generation seeds per iteration.
        chomp(my @files = `ls -fA $TRACEGEN_STAGING_DIR`);
        foreach my $file(@files) {
            my $ctime = stat("$TRACEGEN_STAGING_DIR/$file")->ctime;
            if (time() - $ctime < 30) {
                next;
            }

            my $tracegen_command = "$TRACEGEN_BINARY $TRACEGEN_BINARY_ARGUMENT_TEMPLATE";
            $tracegen_command =~ s,\@\@,$TRACEGEN_STAGING_DIR/$file,;

            my $tracegen_command_pid = fork;
            if (!$tracegen_command_pid) {
                exec $tracegen_command;
            }
            waitpid $tracegen_command_pid, 0;

            my $exit_status = ($? >> 8) == 0 ? "success" : "failure";
            my $input_size = -s "$TRACEGEN_STAGING_DIR/$file";

            # Write the ending trace
            my $NAMED_PIPE = "/tmp/vvdump";
            open TRACEGEN, ">>", $NAMED_PIPE;
            print TRACEGEN "$experiment:$full_subject:$TRACEGEN_BIN_CONTEXT:$TRACEGEN_EXEC_CONTEXT:$tracegen_command_pid:$exit_status:$input_size:end\n";
            close TRACEGEN;

            system "mv $TRACEGEN_STAGING_DIR/$file $TRACEGEN_ITERATION_DIR";
        }

        exit;
    }

    push @CHILDREN, $pid;
    $RUN_ITERATION_TRACEGEN_PIDS->{"$run_name-$iteration"} = $pid;
}
