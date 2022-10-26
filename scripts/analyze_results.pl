#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';

use File::Basename;
use threads;
use threads::shared;
use Thread::Pool;
use Thread::Queue;

use lib glob "~/Projects/phd/scripts/modules";
use analysis;
use utils;
use jsoncpp;

if (! -e -d "/media/2tb/phd-workspace/nfs") {
    die "Should be run on system that has local results\n";
}

my $SCRIPT_NAME = basename $0;

if (scalar @ARGV < 4) {
    die "Syntax: $SCRIPT_NAME <experiment> <subject>[:version] <run-name> <iteration>\n";
}

chomp(my $previous_pid = `ps -u | grep -v grep | grep "$SCRIPT_NAME $ARGV[0] $ARGV[1] $ARGV[2] $ARGV[3]" | grep -v $$ | awk '{ print \$2; }'`);
if ($previous_pid) {
    die "There is already a $SCRIPT_NAME process ($previous_pid) running for the provided arguments\n";
}

my $subject_tracegen_checkers = {
    libpng       => create_wrapped_checker(\&passthru),
    libtpms      => create_wrapped_checker(\&passthru),
    pcapplusplus => create_wrapped_checker(\&passthru),
    dmg2img      => create_wrapped_checker(\&passthru),
    readelf      => create_wrapped_checker(\&passthru),
    jsoncpp      => create_wrapped_checker(\&jsoncpp::check_input_is_valid_json)
};

my $experiment = $ARGV[0];
my $full_subject = $ARGV[1];
my $run_name = $ARGV[2];
my $iteration = $ARGV[3];
my $original_subject = $full_subject;
my $subject = $full_subject;
my $version;
if ($full_subject =~ /:/) {
    ($subject, $version) = split(/:/, $full_subject);
    $full_subject =~ s/:/-/;
}

my $SUBJECT_DIR = utils::get_remote_nfs_subject_directory($experiment, $subject, $version);
my $RUN_DIR = "$SUBJECT_DIR/results/$run_name-$iteration";
my $ANALYZE_RESULTS_LOG_FILENAME = "analyze_results.log";

my $num_jobs :shared = 0;
my $print_remaining :shared = 0;

open LOG, ">", "$RUN_DIR/$ANALYZE_RESULTS_LOG_FILENAME";

my $pool = Thread::Pool->new({
    optimize     => 'memory',
    do           => sub {
        my $session = $_[0];
        my $input_file = $_[1];
        my $count = $_[2];
        my $basic_blocks = analysis::get_basic_blocks_for_input($subject, $input_file, $count);
        process_file_with_coverage_data($session, $input_file, $basic_blocks, $count);
        #return $session, $input_file, analysis::get_basic_blocks_for_input($subject, $input_file, $count), $count;
    },
    stream       => sub {
        $num_jobs--;
        print LOG "$num_jobs files remaining to be processed                   \r" if $print_remaining;
    },
    #stream       => sub {
    #if ($_[0] eq "__COMPLETED__") {
    #    $queue->end();
    #} else {
    #    $queue->enqueue({
    #        session      => $_[0],
    #        input_file   => $_[1],
    #        basic_blocks => $_[2],
    #        count        => $_[3]
    #    });
    #}
    #},
    autoshutdown => 1,
    workers      => 8,
    maxjobs      => 163840,
    minjobs      => 81920,
});

#my $worker = threads->create(
#    sub {
#        # Thread will loop until no more work
#        while(defined(my $item = $queue->dequeue())) {
#            process_file_with_coverage_data($item->{session}, $item->{input_file}, $item->{basic_blocks}, $item->{count});
#        }
#    }
#);

my $shutdown_requested;
my $runs_after_shutdown_request = 0;
until($shutdown_requested && $runs_after_shutdown_request > 0) {
    $shutdown_requested = -e -f "$RUN_DIR/shutdown_analyze_results";
    if ($shutdown_requested) {
        print "\nShutdown requested. Will run one last iteration before shutdown.\n";
        $runs_after_shutdown_request++;
    }

    $print_remaining = 0;

    chomp(my @sessions = `grep "^[^- ]" $RUN_DIR/id_to_pod_name_and_target.yml | sed -e 's,:,,'`);
    analysis::iterate_fuzzer_results(
        $experiment, $subject, $version, "$run_name-$iteration", "sandpuppy", \@sessions,
        \&iteration_handler,
        sub {
            my $line = $_[0];
            print LOG $line;
        }
    );

    truncate LOG, 0;
    #until ($pool->todo() == 0) {
    #    print "${\($pool->todo())} jobs remaining...\r";
    #    sleep 1;
    #}
    #$pool->shutdown();
    #$worker->join();
}


$print_remaining = 1;
$pool->shutdown();
print LOG "\nShutting down\n";
close LOG;

sub iteration_handler {
    my $session = $_[0];
    my $input_file = $_[1];
    my $count = $_[2];
    $pool->job($session, $input_file, $count);
    $num_jobs++;
}

sub process_file_with_coverage_data {
    my $session = $_[0];
    my $input_file = $_[1];
    my $basic_blocks = $_[2];
    my $count = $_[3];

    #print "\n checking coverage file $count $input_file\n";
    my $has_new_coverage;
    {
        #lock($coverage_lock);
        $has_new_coverage = analysis::is_coverage_new(
            $experiment, $subject, $version, $run_name, $iteration, $basic_blocks
        );
    }
    if ($has_new_coverage != 0) {
        # New overall coverage implies new session coverage as well, so let's record session coverage in addition to
        # overall coverage. After this we will copy this input over to be used as a seed in the next iteration.
        #print "\n recording input coverage $count $input_file\n";
        {
            #lock($coverage_lock);
            #lock($session_coverage_lock);
            analysis::record_input_coverage(
                $experiment, $subject, $version, $run_name, $iteration, $input_file, $basic_blocks
            );
            #print "\n recording session input coverage $count $input_file\n";
            analysis::record_session_input_coverage(
                $experiment, $subject, $version, $run_name, $iteration, $session, $input_file, $basic_blocks
            );
        }

        #print "\n copying for next generation of seeds $count $input_file\n";
        analysis::copy_input_for_next_iteration_seeds(
            $experiment, $subject, $version, $run_name, $iteration, $session, $input_file
        );
    } else {
        #print "\n checking new session coverage $count $input_file\n";
        my $has_new_session_coverage;
        {
            #lock($session_coverage_lock);
            $has_new_session_coverage = analysis::is_session_coverage_new(
                $experiment, $subject, $version, $run_name, $iteration, $session, $basic_blocks
            );
        }

        #print "\n session coverage is $has_new_session_coverage and will record for $count $input_file if necessary\n";
        #lock($session_coverage_lock);
        analysis::record_session_input_coverage(
            $experiment, $subject, $version, $run_name, $iteration, $session, $input_file, $basic_blocks
        ) if $has_new_session_coverage != 0;
    }

    # Copy file for tracegen if checker thinks it is valid
    if ($subject_tracegen_checkers->{$subject}->($input_file) != 0) {
        #print "\nfile is valid for tracegen $count $input_file\n";
        analysis::copy_input_for_tracegen(
            $experiment, $subject, $version, $run_name, $iteration, $session, $input_file
        );
    }
}

sub create_wrapped_checker {
    my $checker = $_[0];
    return sub {
        my $input_file = $_[0];
        #print "\n checking $input_file\n";
        return analysis::check_if_input_processed_successfully($subject, $input_file) && $checker->($input_file);
    }
}

sub passthru {
    return 1;
}
