#!/usr/bin/perl

use lib glob "~/Projects/phd/scripts/modules";
use strict;
use warnings FATAL => 'all';
use POSIX;

use tasks;

if (!-e "/tmp/vvdump") {
    POSIX::mkfifo("/tmp/vvdump", 0700) or die "Could not create /tmp/vvdump";
}

my $supported_tasks = {
    build  => 1,
    fuzz   => 1,
    spfuzz => 1
};

if (scalar @ARGV < 5) {
    die "Syntax:\n $0 <experiment> build <subject>[:<version>] with waypoints <waypoints> as <binary-context>" .
        "\n $0 <experiment> fuzz <subject>[:<version>]  with waypoints <waypoints> using <binary-context> as <exec-context>" .
        "\n $0 <experiment> spfuzz <subject>[:<version>] [with asan]\n";
}

my $experiment_name = $ARGV[0];

my $task = $ARGV[1];
if (!$supported_tasks->{$task}) {
    die "Unsupported task $task; supported tasks are " . join(", ", keys(%{$supported_tasks}));
}

my $full_subject = $ARGV[2]; # this single param should let me identify source dir for building
my $original_subject = $full_subject;
my $subject = $full_subject;
my $version;
if ($full_subject =~ /:/) {
    ($subject, $version) = split(/:/, $full_subject);
    $full_subject =~ s/:/-/;
}

my $waypoints;
my $binary_context;
my $execution_context;
my $use_asan;
if ($task eq "build" or $task eq "fuzz") {
    if ($ARGV[3] ne "with" && $ARGV[4] ne "waypoints") {
        die "Expected \"with waypoints\":\n $0 $experiment_name $task $original_subject with waypoints <waypoints> ...";
    }

    $waypoints = $ARGV[5];
    if ($task eq "build") {
        if ($ARGV[6] ne "as") {
            die "Expected \"as\":\n $0 $experiment_name $task $original_subject with waypoints $waypoints as <binary-context>";
        }

        if (!$ARGV[7]) {
            die "Expected <binary-context>:\n $0 $experiment_name $task $original_subject with waypoints $waypoints as <binary-context>";
        }

        $binary_context = $ARGV[7];
    }

    if ($task eq "fuzz") {
        if ($ARGV[6] ne "using") {
            die "Expected \"using\":\n $0 $experiment_name $task $original_subject with waypoints $waypoints using <binary-context> as <exec-context>";
        }

        if (!$ARGV[7]) {
            die "Expected <binary-context>:\n $0 $experiment_name $task $original_subject with waypoints $waypoints using <binary-context> as <exec-context>";
        }

        $binary_context = $ARGV[7];

        if ($ARGV[8] ne "as") {
            die "Expected \"as\":\n $0 $experiment_name $task $original_subject with waypoints $waypoints using $binary_context as <exec-context>";
        }

        if (!$ARGV[9]) {
            die "Expected <exec-context>:\n $0 $experiment_name $task $original_subject with waypoints $waypoints using $binary_context as <exec-context>";
        }

        $execution_context = $ARGV[9];
    }
} else {
    if ($ARGV[3] && $ARGV[3] ne "with") {
        die "Expected \"with\":\n $0 $experiment_name $task $original_subject with asan";
    } elsif ($ARGV[3] && $ARGV[4] && $ARGV[4] ne "asan") {
        die "Expected \"asan\":\n $0 $experiment_name $task $original_subject with asan";
    } elsif ($ARGV[4]) {
        $use_asan = 1;
    }
}

if (!tasks::subject_exists($subject)) {
    die "Unrecognized subject $subject";
}

if ($task ne "spfuzz" && !tasks::subject_has_task($subject, $task)) {
    die "Subject $subject does not have task $task"
}

if ($task eq "build") {
    tasks::initialize_workspace($experiment_name, $subject, $version);
    tasks::build($experiment_name, $subject, $version, $waypoints, $binary_context, {});
} else {
    my $workspace = utils::get_workspace($experiment_name, $subject, $version);
    if (! -d $workspace) {
        die "Cannot run $task because experiment and subject workspace $workspace does not exist";
    }

    if ($task eq "fuzz") {
        tasks::fuzz($experiment_name, $subject, $version, $waypoints, $binary_context, $execution_context);
    } elsif ($task eq "spfuzz") {
        tasks::sandpuppy_fuzz($experiment_name, $subject, $version, { use_asan => $use_asan });
    }
}
