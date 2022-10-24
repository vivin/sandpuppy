#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';

use lib glob "~/Projects/phd/scripts/modules";
use analysis;
use utils;
use jsoncpp;
use Time::HiRes qw(time);

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

my $SUBJECT_DIR = utils::get_remote_nfs_subject_directory($experiment, $subject, $version);
my $RUN_DIR = "$SUBJECT_DIR/results/$run_name-$iteration";
chomp(my @sessions = `grep "^[^- ]" $RUN_DIR/id_to_pod_name_and_target.yml | sed -e 's,:,,'`);
analysis::iterate_fuzzer_results(
    $experiment, $subject, $version, "$run_name-$iteration", "sandpuppy", \@sessions,
    \&iteration_handler
);

print "Analysis done!\n";

sub iteration_handler {
    my $session = $_[0];
    my $input_file = $_[1];

    my $start = time();
    my @basic_blocks = @{analysis::get_basic_blocks_for_input($subject, $input_file)};
    my $has_new_coverage = analysis::is_coverage_new(
        $experiment, $subject, $version, $run_name, $iteration, \@basic_blocks
    );
    if ($has_new_coverage != 0) {
        # New overall coverage implies new session coverage as well, so let's record session coverage in addition to
        # overall coverage. After this we will copy this input over to be used as a seed in the next iteration.
        analysis::record_input_coverage(
            $experiment, $subject, $version, $run_name, $iteration, $input_file, \@basic_blocks
        );
        analysis::record_session_input_coverage(
            $experiment, $subject, $version, $run_name, $iteration, $session, $input_file, \@basic_blocks
        );
        analysis::copy_input_for_next_iteration_seeds(
            $experiment, $subject, $version, $run_name, $iteration, $session, $input_file
        );
    } else {
        my $has_new_session_coverage = analysis::is_session_coverage_new(
            $experiment, $subject, $version, $run_name, $iteration, $session, \@basic_blocks
        );
        analysis::record_session_input_coverage(
            $experiment, $subject, $version, $run_name, $iteration, $session, $input_file, \@basic_blocks
        ) if $has_new_session_coverage != 0;
    }

    # Copy file for tracegen if checker thinks it is valid
    if ($subject_tracegen_checkers->{$subject}->($input_file) != 0) {
        analysis::copy_input_for_tracegen(
            $experiment, $subject, $version, $run_name, $iteration, $session, $input_file
        );
    }

    my $elpsd = time() - $start; printf "\nelapsed: %.9f\n", $elpsd;
}

sub create_wrapped_checker {
    my $checker = $_[0];
    return sub {
        my $input_file = $_[0];
        return analysis::check_if_input_processed_successfully($subject, $input_file) == 1 && $checker->($input_file) == 1;
    }
}

sub passthru {
    return 1;
}
