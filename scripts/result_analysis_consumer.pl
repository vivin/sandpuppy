#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';

use File::Basename;
use Redis;

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

my $subject_tracegen_checkers = {
    libpng       => create_wrapped_checker("libpng", \&passthru),
    libtpms      => create_wrapped_checker("libtpms", \&passthru),
    pcapplusplus => create_wrapped_checker("pcapplusplus", \&passthru),
    dmg2img      => create_wrapped_checker("dmg2img", \&passthru),
    readelf      => create_wrapped_checker("readelf", \&passthru),
    jsoncpp      => create_wrapped_checker("jsoncpp", \&jsoncpp::check_input_is_valid_json)
};

chomp(my $redis_credentials = `cat $BASE_NFS_PATH/redis-credentials`);
my $redis = Redis->new(
    server   => "vivin.is-a-geek.net:16379",
    password => $redis_credentials
);
my $redis_status_client = Redis->new(
    server   => "vivin.is-a-geek.net:16379",
    password => $redis_credentials
);

$redis->subscribe(
    $CHANNEL_NAME,
    \&subscribe_handler
);
$redis->wait_for_messages(5) while 1;

sub subscribe_handler {
    my ($message, $topic, $subscribed_topic) = @_;
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
    my $has_new_coverage = analysis::is_coverage_new(
        $experiment, $subject, $version, $run_name, $iteration, $basic_blocks
    );
    if ($has_new_coverage != 0) {
        # New overall coverage implies new session coverage as well, so let's record session coverage in addition to
        # overall coverage. After this we will copy this input over to be used as a seed in the next iteration.
        analysis::record_input_coverage(
            $experiment, $subject, $version, $run_name, $iteration, $input_file, $basic_blocks, $ctime
        );
        analysis::record_session_input_coverage(
            $experiment, $subject, $version, $run_name, $iteration, $session, $input_file, $basic_blocks, $ctime
        );
        analysis::copy_input_for_next_iteration_seeds(
            $experiment, $subject, $version, $run_name, $iteration, $session, $input_file
        );
    } else {
        my $has_new_session_coverage = analysis::is_session_coverage_new(
            $experiment, $subject, $version, $run_name, $iteration, $session, $basic_blocks
        );
        analysis::record_session_input_coverage(
            $experiment, $subject, $version, $run_name, $iteration, $session, $input_file, $basic_blocks, $ctime
        ) if $has_new_session_coverage != 0;
    }

    # Copy file for tracegen if checker thinks it is valid
    if ($subject_tracegen_checkers->{$subject}->($input_file) != 0) {
        analysis::copy_input_for_tracegen(
            $experiment, $subject, $version, $run_name, $iteration, $session, $input_file
        );
    }

    my $processed_files_key = "$experiment:$full_subject:$run_name-$iteration.processed_files";
    $redis_status_client->incr($processed_files_key);
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
