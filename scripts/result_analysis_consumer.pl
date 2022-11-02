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

my $SCRIPT_NAME = basename $0;
if (scalar @ARGV == 0) {
    die "Syntax: $SCRIPT_NAME <channel-name>";
}

my $CHANNEL_NAME = $ARGV[0];

my $BASE_NFS_PATH = utils::get_base_container_nfs_path();
if (! -e -f "$BASE_NFS_PATH/redis-credentials") {
    die "Could not find redis credentials\n";
}

chomp(my $NUM_CPUS = `lscpu | grep "CPU(s):" | head -1 | awk '{ print \$2; }'`);
my $NUM_WORKERS = $NUM_CPUS;
my $NUM_REDIS_CLIENTS = $NUM_CPUS;

my $REDIS_HOST = $ENV{REDIS_SERVICE_HOST};
my $REDIS_PORT = $ENV{REDIS_SERVICE_PORT};

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

my $subject_tracegen_checkers = {
    libpng       => create_wrapped_checker("libpng", \&passthru),
    libtpms      => create_wrapped_checker("libtpms", \&passthru),
    pcapplusplus => create_wrapped_checker("pcapplusplus", \&passthru),
    dmg2img      => create_wrapped_checker("dmg2img", \&passthru),
    readelf      => create_wrapped_checker("readelf", \&passthru),
    jsoncpp      => create_wrapped_checker("jsoncpp", \&jsoncpp::check_input_is_valid_json)
};

my $redis_subscriber_client = Redis->new(
    server   => "$REDIS_HOST:$REDIS_PORT"
);

my $pool = Thread::Pool->new({
    optimize     => 'memory',
    do           => \&subscribe_handler,
    autoshutdown => 1,
    workers      => $NUM_WORKERS,
    maxjobs      => 163840,
    minjobs      => 81920,
});

print "Listening on channel $CHANNEL_NAME with $NUM_WORKERS workers...\n";
while (1) {
    my $message = $redis_subscriber_client->brpop($CHANNEL_NAME, 5);
    if (defined $message) {
        $pool->job(@{$message});
    }
}

sub subscribe_handler {
    my ($topic, $message) = @_;
    print "Received message from topic $topic: $message\n";

    my ($experiment, $full_subject, $run_name, $iteration, $session, $input_file, $ctime) = split /#/, $message;
    my $original_subject = $full_subject;
    my $subject = $full_subject;
    my $version;
    if ($full_subject =~ /:/) {
        ($subject, $version) = split(/:/, $full_subject);
        $full_subject =~ s/:/-/;
    }

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
}

sub create_wrapped_checker {
    my $subject = $_[0];
    my $checker = $_[1];
    return sub {
        my $input_file = $_[0];
        return analysis::check_if_input_processed_successfully($subject, $input_file) && $checker->($input_file);
    }
}

sub passthru {
    return 1;
}
