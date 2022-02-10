#!/usr/bin/perl

use lib glob "~/Projects/phd/scripts/modules";
use strict;
use warnings FATAL => 'all';
use POSIX;
use Fcntl;
use tasks;

my $supported_tasks = {
    build         => 1,
    fuzz          => 1,
    spfuzz        => 1,
    spvanillafuzz => 1
};

if (scalar @ARGV < 3) {
    die "Syntax:\n $0 <experiment> build <subject>[:<version>] with waypoints <waypoints> as <binary-context>" .
        "\n $0 <experiment> fuzz <subject>[:<version>] with waypoints <waypoints> using <binary-context> as <exec-context> [resume]" .
        "\n $0 <experiment> spfuzz <subject>[:<version>] as <run-name> [resume | with asan [resume]]\n";
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
my $use_asan = 0;
my $resume = 0;
my $run_name = "";
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

        if ($ARGV[10] && $ARGV[10] ne "resume") {
            die "Expected \"resume\":\n $0 $experiment_name $task $original_subject with waypoints $waypoints using $binary_context as $execution_context resume";
        } elsif ($ARGV[10] && $ARGV[10] eq "resume") {
            $resume = 1;
        }
    }
} elsif ($task eq "spfuzz" || $task eq "spvanillafuzz") {
    if (!$ARGV[3] || $ARGV[3] ne "as") {
        die "Expected \"as\":\n $0 $experiment_name $task $original_subject as <run-name> [resume | with asan [resume]]\n";
    } elsif (!$ARGV[4]) {
        die "Expected <run-name>:\n $0 $experiment_name $task $original_subject as <run-name> [resume | with asan [resume]]\n";
    }

    $run_name = $ARGV[4];

    if ($ARGV[5] && $ARGV[5] ne "resume" && $ARGV[5] ne "with") {
        die "Expected \"resume\":\n $0 $experiment_name $task $original_subject as $run_name resume\n   or   \nExpected \"with\":\n $0 $experiment_name $task $original_subject as $run_name with asan [resume]";
    } elsif ($ARGV[5] && $ARGV[5] eq "with" && (!$ARGV[6] || $ARGV[6] ne "asan")) {
        die "Expected \"asan\":\n $0 $experiment_name $task $original_subject as <run-name> with asan [resume]\n";
    } elsif ($ARGV[5] && $ARGV[5] eq "with") {
        $use_asan = 1;

        if ($ARGV[7] && $ARGV[7] ne "resume") {
            die "Expected \"resume\":\n $0 $experiment_name $task $original_subject as <run-name> with asan resume\n";
        } elsif ($ARGV[7]) {
            $resume = 1;
        }
    } elsif ($ARGV[5]) {
        $resume = 1;
    }
} else {
    die "Unrecognized task: $task\n";
}

if (!tasks::subject_exists($subject)) {
    die "Unrecognized subject $subject";
}

if ($task ne "spfuzz" && $task ne "spvanillafuzz" && !tasks::subject_has_task($subject, $task)) {
    die "Subject $subject does not have task $task"
}

if ($task eq "build") {
    tasks::initialize_subject_directory($experiment_name, $subject, $version);
    tasks::build($experiment_name, $subject, $version, $waypoints, $binary_context, {});
} else {
    my $subject_directory = utils::get_subject_directory($experiment_name, $subject, $version);
    if (! -d $subject_directory) {
        die "Cannot run $task because subject directory $subject_directory does not exist";
    }

    if ($task eq "fuzz") {
        if ($waypoints =~ /vvdump/) {
            tasks::vvdump_fuzz($experiment_name, $subject, $version, $waypoints, $binary_context, $execution_context, { resume => $resume });
        } else {
            tasks::fuzz($experiment_name, $subject, $version, $waypoints, $binary_context, $execution_context, { resume => $resume });
        }
    } elsif ($task eq "spfuzz" || $task eq "spvanillafuzz") {
        my $nfs_subject_directory = utils::get_nfs_subject_directory($experiment_name, $subject, $version);
        if (-d "$nfs_subject_directory/results/$run_name/sandpuppy-sync" && !$resume) {
            die "Results directory already exists at $nfs_subject_directory/results/$run_name/sandpuppy-sync! Maybe try resuming?";
        }

        if ($task eq "spfuzz") {
            tasks::sandpuppy_fuzz(
                $experiment_name,
                $subject,
                $version,
                {
                    run_name => $run_name,
                    use_asan => $use_asan,
                    resume   => $resume
                }
            );
        } else {
            tasks::sandpuppy_vanilla_fuzz(
                $experiment_name,
                $subject,
                $version,
                {
                    run_name => $run_name,
                    use_asan => $use_asan,
                    resume   => $resume
                }
            );
        }

    }
}
