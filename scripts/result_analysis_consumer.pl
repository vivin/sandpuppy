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
    libpng       => create_subject_file_checker("libpng", create_sampling_checker(.01, \&passthru)),
    libtpms      => create_subject_file_checker("libtpms", create_sampling_checker(.01, \&passthru)),
    pcapplusplus => create_subject_file_checker("pcapplusplus", create_sampling_checker(.001, \&passthru)), # .001
    dmg2img      => create_subject_file_checker("dmg2img", create_sampling_checker(.01, \&passthru)), #.01
    readelf      => create_subject_file_checker("readelf", create_sampling_checker(.02, \&passthru)), #.02
    jsoncpp      => create_subject_file_checker("jsoncpp", create_sampling_checker(.1, \&jsoncpp::check_input_is_valid_json)),
    ffmpeg       => create_subject_file_checker("ffmpeg", create_sampling_checker(.01, \&passthru)) #.01
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

sub create_subject_file_checker {
    my $subject = $_[0];
    my $checker = $_[1];
    return sub {
        my $input_file = $_[0];
        return analysis::check_if_input_processed_successfully($subject, $input_file) && $checker->($input_file);
    }
}

sub create_sampling_checker {
    my $probability = $_[0];
    my $checker = $_[1];

    my $num_total_outcomes = 1;
    my $num_desired_outcomes = 0;
    until ($probability - int($probability) == 0) {
        $num_total_outcomes *= 10;
        $probability *= 10;

        $num_desired_outcomes = $probability;
    }

    if ($num_desired_outcomes % 2 == 0 || $num_desired_outcomes % 5 == 0) {
        my $divisor = ($num_desired_outcomes % 2 == 0) ? 2 : 5;
        until ($num_desired_outcomes % $divisor != 0 || $num_total_outcomes % $divisor != 0) {
            $num_desired_outcomes /= $divisor;
            $num_total_outcomes /= $divisor;
        }
    }

    my @desired_outcomes = ();
    until (scalar @desired_outcomes == $num_desired_outcomes) {
        my $number = int(rand($num_total_outcomes));
        if (! grep /^$number$/, @desired_outcomes) {
            push @desired_outcomes, $number;
        }
    }

    return sub {
        my $input_file = $_[0];

        if ($input_file =~ /\+cov/) {
            return $checker->($input_file);
        }

        if ($input_file !~ /\+tci/) {
            return 0;
        }

        if (grep /^${\(int(rand($num_total_outcomes)))}$/, @desired_outcomes) {
            return $checker->($input_file);
        }

        return 0;
    }
}

sub passthru {
    return 1;
}
