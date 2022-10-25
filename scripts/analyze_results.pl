#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';

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

if (scalar @ARGV < 4) {
    die "Syntax: $0 <experiment> <subject>[:version] <run-name> <iteration>\n";
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

my $queue = Thread::Queue->new();
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
    maxjobs      => 40,
    minjobs      => 20,
});

#my $worker = threads->create(
#    sub {
#        # Thread will loop until no more work
#        while(defined(my $item = $queue->dequeue())) {
#            process_file_with_coverage_data($item->{session}, $item->{input_file}, $item->{basic_blocks}, $item->{count});
#        }
#    }
#);

my $SUBJECT_DIR = utils::get_remote_nfs_subject_directory($experiment, $subject, $version);
my $RUN_DIR = "$SUBJECT_DIR/results/$run_name-$iteration";
chomp(my @sessions = `grep "^[^- ]" $RUN_DIR/id_to_pod_name_and_target.yml | sed -e 's,:,,'`);
analysis::iterate_fuzzer_results(
    $experiment, $subject, $version, "$run_name-$iteration", "sandpuppy", \@sessions,
    \&iteration_handler
);
$pool->shutdown();
#$worker->join();

print "Analysis done!\n";

sub iteration_handler {
    my $session = $_[0];
    my $input_file = $_[1];
    my $count = $_[2];
    $pool->job($session, $input_file, $count);
}

sub process_file_with_coverage_data {
    my $session = $_[0];
    my $input_file = $_[1];
    my @basic_blocks = $_[2];
    my $count = $_[3];

    my $coverage_lock :shared;
    my $session_coverage_lock :shared;
    #print "\n checking coverage file $count $input_file\n";
    my $has_new_coverage;
    {
        lock($coverage_lock);
        $has_new_coverage = analysis::is_coverage_new(
            $experiment, $subject, $version, $run_name, $iteration, \@basic_blocks
        );
    }
    if ($has_new_coverage != 0) {
        # New overall coverage implies new session coverage as well, so let's record session coverage in addition to
        # overall coverage. After this we will copy this input over to be used as a seed in the next iteration.
        #print "\n recording input coverage $count $input_file\n";
        lock($coverage_lock);
        lock($session_coverage_lock);
        analysis::record_input_coverage(
            $experiment, $subject, $version, $run_name, $iteration, $input_file, \@basic_blocks
        );
        #print "\n recording session input coverage $count $input_file\n";
        analysis::record_session_input_coverage(
            $experiment, $subject, $version, $run_name, $iteration, $session, $input_file, \@basic_blocks
        );

        #print "\n copying for next generation of seeds $count $input_file\n";
        analysis::copy_input_for_next_iteration_seeds(
            $experiment, $subject, $version, $run_name, $iteration, $session, $input_file
        );
    } else {
        #print "\n checking new session coverage $count $input_file\n";
        my $has_new_session_coverage;
        {
            lock($session_coverage_lock);
            $has_new_session_coverage = analysis::is_session_coverage_new(
                $experiment, $subject, $version, $run_name, $iteration, $session, \@basic_blocks
            );
        }

        #print "\n session coverage is $has_new_session_coverage and will record for $count $input_file if necessary\n";
        lock($session_coverage_lock);
        analysis::record_session_input_coverage(
            $experiment, $subject, $version, $run_name, $iteration, $session, $input_file, \@basic_blocks
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
