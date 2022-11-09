#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';

use File::Basename;
use Redis;
use Thread::Pool;
use Thread::Queue;

use lib glob "~/Projects/phd/scripts/modules";
use analysis;
use utils;
use jsoncpp;

my $BASE_PATH = glob "~/Projects/phd";
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

my $NUM_CPUS = 8;
my $NUM_WORKERS = $NUM_CPUS;
my $NUM_REDIS_CLIENTS = $NUM_CPUS;

my @redis_client_pool = map {
    Redis->new(
        server                 => "206.206.192.29:31111",
        conservative_reconnect => 1,
        cnx_timeout            => 900,
        reconnect              => 900
    );
} (1..$NUM_REDIS_CLIENTS);

my $client_index_queue = Thread::Queue->new();
$client_index_queue->enqueue((0..$NUM_REDIS_CLIENTS - 1));

my $redis_status_client = Redis->new(
    server                 => "206.206.192.29:31111",
    conservative_reconnect => 1,
    cnx_timeout            => 900,
    reconnect              => 900
);

my $fuzz_config = YAML::XS::LoadFile("$BASE_PATH/resources/fuzz_config.yml");

open LOG, ">", "$RUN_DIR/$ANALYZE_RESULTS_LOG_FILENAME";

my $pool = Thread::Pool->new({
    optimize     => 'memory',
    do           => sub {
        my $message = $_[0];

        my ($session, $input_file, $ctime) = split /#/, $message;

        my $basic_blocks = analysis::get_basic_blocks_for_input($subject, $input_file);

        my $client_pool_index = $client_index_queue->dequeue();
        my $redis = $redis_client_pool[$client_pool_index];

        my $has_new_coverage = analysis::is_coverage_new(
            $redis, $experiment, $subject, $version, $run_name, $iteration, $basic_blocks
        );
        if ($has_new_coverage != 0) {
            # New overall coverage implies new session coverage as well, so let's record session coverage in addition to
            # overall coverage. After this we will copy this input over to be used as a seed in the next iteration.
            analysis::record_input_coverage(
                $redis, $experiment, $subject, $version, $run_name, $iteration, $input_file, $basic_blocks, $ctime
            );
            analysis::record_session_input_coverage(
                $redis, $experiment, $subject, $version, $run_name, $iteration, $session, $input_file, $basic_blocks, $ctime
            );
            analysis::copy_input_for_next_iteration_seeds(
                $experiment, $subject, $version, $run_name, $iteration, $session, $input_file
            );
        } else {
            my $has_new_session_coverage = analysis::is_session_coverage_new(
                $redis, $experiment, $subject, $version, $run_name, $iteration, $session, $basic_blocks
            );
            analysis::record_session_input_coverage(
                $redis, $experiment, $subject, $version, $run_name, $iteration, $session, $input_file, $basic_blocks, $ctime
            ) if $has_new_session_coverage != 0;
        }

        # Copy file for tracegen if checker thinks it is valid
        if ($subject_tracegen_checkers->{$subject}->($input_file) != 0) {
            analysis::copy_input_for_tracegen(
                $experiment, $subject, $version, $run_name, $iteration, $session, $input_file
            );
        }

        my $processed_files_key = "$experiment:$full_subject:$run_name-$iteration.processed_files";
        $redis->incr($processed_files_key);

        $client_index_queue->enqueue($client_pool_index);
    },
    autoshutdown => 1,
    workers      => $NUM_WORKERS,
    maxjobs      => 163840,
    minjobs      => 81920,
});

my $shutdown_requested;
my $runs_after_shutdown_request = 0;
until($shutdown_requested && $runs_after_shutdown_request > 0) {
    $shutdown_requested = -e -f "$RUN_DIR/shutdown_analyze_results";
    if ($shutdown_requested) {
        print "\nShutdown requested. Will wait for 60 seconds so files are old enough to process and then run one more iteration\n";
        $runs_after_shutdown_request++;

        my $time = 60;
        do {
            sleep 1;
            $time--;
            print "$time seconds remaining...\r";
        } until ($time == 0);

        print "\n";
    }

    chomp(my @sessions = `grep "^[^- ]" $RUN_DIR/id_to_pod_name_and_target.yml | sed -e 's,:,,'`);
    utils::iterate_fuzzer_results(
        $experiment, $subject, $version, "$run_name-$iteration", "sandpuppy", \@sessions,
        \&iteration_handler,
        sub {
            my $line = $_[0];
            print LOG $line;
        }
    );

    truncate LOG, 1024;
}

my $done = 0;
until ($done) {
    my $total_files_key = "$experiment:$full_subject:$run_name-$iteration.total_files";
    my $total_files = $redis_status_client->get($total_files_key);

    my $processed_files_key = "$experiment:$full_subject:$run_name-$iteration.processed_files";
    my $processed_files = $redis_status_client->get($processed_files_key);

    print "Files remaining to be processed: ${\($total_files - $processed_files)}\r";
    $done = ($total_files - $processed_files) == 0;
}

$pool->shutdown();
print "\nShutting Down\n";

sub iteration_handler {
    my $session = $_[0];
    my $input_file = $_[1];
    my $ctime = $_[2];

    my $total_files_key = "$experiment:$full_subject:$run_name-$iteration.total_files";
    $redis_status_client->incr($total_files_key);

    $pool->job("$session#$input_file#$ctime");
}

sub create_wrapped_checker {
    my $checker = $_[0];
    return sub {
        my $input_file = $_[0];
        return analysis::check_if_input_processed_successfully($subject, $input_file) && $checker->($input_file);
    }
}

sub passthru {
    return 1;
}
