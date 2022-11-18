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
my $NUM_CONSUMERS = $fuzz_config->{__global__}->{num_consumers};

open LOG, ">", "$RUN_DIR/$ANALYZE_RESULTS_LOG_FILENAME";

my $pool = Thread::Pool->new({
    optimize     => 'memory',
    do           => sub {
        my ($channel, $message) = @_;
        my $client_pool_index = $client_index_queue->dequeue();
        my $redis = $redis_client_pool[$client_pool_index];

        my $total_files_key = "$experiment:$full_subject:$run_name-$iteration.total_files";
        $redis->incr($total_files_key);

        $redis->lpush($channel, $message);

        $client_index_queue->enqueue($client_pool_index);
    },
    autoshutdown => 1,
    workers      => $NUM_WORKERS,
    maxjobs      => 163840,
    minjobs      => 81920,
});

if (-e -f "$RUN_DIR/shutdown_analyze_results_completed") {
    system "rm $RUN_DIR/shutdown_analyze_results_completed";
}

my $channel_number = 1;
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

    truncate LOG, 256;
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

system "touch $RUN_DIR/shutdown_analyze_results_completed";
until (-e -f "$RUN_DIR/shutdown_analyze_results_completed") {
    print "\nShutting Down\n";
    sleep 1;
}

$pool->shutdown();

sub iteration_handler {
    my $session = $_[0];
    my $input_file = $_[1];
    my $ctime = $_[2];

    my $CONTAINER_SUBJECT_DIR = utils::get_container_nfs_subject_directory($experiment, $subject, $version);
    my $renamed_file = $input_file;
    $renamed_file =~ s,^.*results/,$CONTAINER_SUBJECT_DIR/results/,;

    $pool->job(
        "sandpuppy-analysis-channel",
        "$experiment#$original_subject#$run_name#$iteration#$session#$renamed_file#$ctime"
    );

    $channel_number = ($channel_number % $NUM_CONSUMERS) + 1;
}
