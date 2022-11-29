#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';

use File::Basename;
use Redis;
use Thread::Pool;
use Thread::Queue;
use Time::HiRes qw(time);

use lib glob "~/Projects/phd/scripts/modules";
use analysis;
use utils;
use jsoncpp;

my $SCRIPT_NAME = basename $0;
if (scalar @ARGV == 0) {
    die "Syntax: $SCRIPT_NAME <channel-name>";
}

my $CHANNEL_NAME = "sandpuppy-analysis-channel";

my $REDIS_HOST = $ENV{REDIS_SERVICE_HOST};
my $REDIS_PORT = $ENV{REDIS_SERVICE_PORT};

srand time;

my $subject_tracegen_checkers = {
    libpng       => create_wrapped_checker("libpng", \&passthru),
    libtpms      => create_wrapped_checker("libtpms", \&passthru),
    pcapplusplus => create_wrapped_checker("pcapplusplus", \&sampling_passthru),
    dmg2img      => create_wrapped_checker("dmg2img", \&sampling_passthru),
    readelf      => create_wrapped_checker("readelf", \&sampling_passthru),
    jsoncpp      => create_wrapped_checker("jsoncpp", \&jsoncpp::check_input_is_valid_json)
};

my $redis = Redis->new(
    server   => "$REDIS_HOST:$REDIS_PORT",
    conservative_reconnect => 1,
    cnx_timeout            => 900,
    reconnect              => 900
);

print "Listening on channel $CHANNEL_NAME...\n";
while (1) {
    my $message = $redis->brpop($CHANNEL_NAME, 5);
    if (defined $message) {
        subscribe_handler(@{$message});
    }
}

sub subscribe_handler {
    my ($topic, $message) = @_;
    my $start = time();
    print "Received message from topic $topic: $message\n";

    my ($experiment, $full_subject, $run_name, $iteration, $session, $input_file, $ctime) = split /#/, $message;
    my $original_subject = $full_subject;
    my $subject = $full_subject;
    my $version;
    if ($full_subject =~ /:/) {
        ($subject, $version) = split(/:/, $full_subject);
        $full_subject =~ s/:/-/;
    }

    if ($input_file =~ /\+cov/) {
        my $basic_blocks = analysis::get_basic_blocks_for_input($subject, $input_file);

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
    } elsif ($input_file =~ /,orig/) {
        analysis::copy_input_for_next_iteration_seeds(
            $experiment, $subject, $version, $run_name, $iteration, $session, $input_file
        );
    }

    # Copy file for tracegen if checker thinks it is valid and if it is not an original seed (we already have traces
    # from it).
    if ($input_file !~ /,orig/ && $subject_tracegen_checkers->{$subject}->($input_file) != 0) {
        analysis::copy_input_for_tracegen(
            $experiment, $subject, $version, $run_name, $iteration, $session, $input_file
        );
    }

    my $processed_files_key = "$experiment:$full_subject:$run_name-$iteration.processed_files";
    $redis->incr($processed_files_key);

    my $elapsed = time() - $start;
    print "Done in $elapsed ms...\n";
}

sub create_wrapped_checker {
    my $subject = $_[0];
    my $checker = $_[1];
    return sub {
        my $input_file = $_[0];
        return analysis::check_if_input_processed_successfully($subject, $input_file) && $checker->($input_file);
    }
}

sub sampling_passthru {
    my $input_file = $_[0];

    if ($input_file =~ /\+cov/) {
        return 1;
    }

    my $val = int(rand(10));
    return $val == 7 # only pass through 7% otherwise
}

sub passthru {
    return 1;
}
