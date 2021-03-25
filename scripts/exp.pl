#!/usr/bin/perl

use lib glob "~/Projects/phd/scripts/modules";
use strict;
use warnings;
use Log::Simple::Color;
use File::Path qw(make_path);
use Time::HiRes qw(time);
use POSIX;
use YAML::XS;

use infantheap;
use rarebug;
use maze;
use libpng;
use readelf;
use libtpms;

if (!-e "/tmp/vvdump") {
    POSIX::mkfifo("/tmp/vvdump", 0700) or die "Could not create /tmp/vvdump";
}

my $log = Log::Simple::Color->new;

my $BASEPATH = glob "~/Projects/phd";
my $BASEWORKSPACEPATH = "$BASEPATH/workspace";
my $TOOLS = "$BASEPATH/tools";

my $supported_tasks = {
    build  => 1,
    fuzz   => 1,
    spfuzz => 1
};

my $subjects = {
    infantheap => {
        tasks     => {
            build => \&infantheap::build,
            fuzz  => \&infantheap::fuzz
        },
        fuzz_time => 600
    },
    rarebug    => {
        tasks     => {
            build => \&rarebug::build,
            fuzz  => \&rarebug::fuzz
        },
        fuzz_time => 600
    },
    maze       => {
        tasks     => {
            build => \&maze::build,
            fuzz  => \&maze::fuzz
        },
        fuzz_time => 1200
    },
    libpng     => {
        tasks     => {
            build => \&libpng::build,
            fuzz  => \&libpng::fuzz
        },
        fuzz_time => 14400
    },
    readelf    => {
        tasks     => {
            build => \&readelf::build,
            fuzz  => \&readelf::fuzz
        },
        fuzz_time => 7200
    },
    libtpms    => {
        tasks     => {
            build => \&libtpms::build,
            fuzz  => \&libtpms::fuzz
        },
        fuzz_time => 14400
    }
};

if (scalar @ARGV < 5) {
    die "Syntax:\n $0 <experiment> build <subject>[:<version>] with waypoints <waypoints> as <binary-context>" .
        "\n $0 <experiment> fuzz <subject>[:<version>]  with waypoints <waypoints> using <binary-context> as <exec-context>" .
        "\n $0 <experiment> spfuzz <subject>[:<version>] using <exec-context>\n";
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
}
else {
    if ($ARGV[3] ne "using") {
        die "Expected \"using\":\n $0 $experiment_name $task $original_subject using <exec-context>";
    }

    $execution_context = $ARGV[4];
}

my $workspace = "$BASEWORKSPACEPATH/$experiment_name/$full_subject";
if (!-d $workspace) {
    $log->info("Creating $workspace");
    make_path($workspace);
}

if (!-d "$workspace/binaries") {
    $log->info("Creating $workspace/binaries");
    make_path("$workspace/binaries");
}

if (!-d "$workspace/results") {
    $log->info("Creating $workspace/results");
    make_path("$workspace/results");
}

if (!$subjects->{$subject}) {
    die "No subject named $subject";
}

if ($task eq "build") {
    &build;
} elsif ($task eq "fuzz") {
    &fuzz;
} elsif ($task eq "spfuzz") {
    &sandpuppy_fuzz;
}

sub sandpuppy_fuzz {
    my $results_dir = "$workspace/results/$execution_context";
    if (!-d $results_dir) {
        die "Could not find results directory $results_dir to use for sandpuppy fuzzing.";
    }

    my $variable_targets_file = "$results_dir/sandpuppy_variable_targets.yml";
    if (!-f $variable_targets_file) {
        die "Could not find variable targets file $variable_targets_file to use for sandpuppy fuzzing.";
    }

    my $tasks = $subjects->{$subject}->{tasks};
    if (!$tasks) {
        die "No tasks for $subject.";
    }

    if (!$tasks->{build}) {
        die "No build task for $subject.";
    }

    # Generate variable files. This function returns a map with three keys. The max key is associated with a single
    # map containing a name key and a variables_file key. The name key is just an id for the instrumentation and the
    # variables_file key is the path to the variables file for the corresponding instrumentation (in this case vvmax).
    # The remaining two keys, perm and hash, are associated with an array of maps like the one described above.
    my $targets = &generate_variable_files($variable_targets_file);

    # First we will build a version with just ASAN and regular AFL instrumentation. This will be used in the parent
    # fuzzer.
    &{$tasks->{build}}($experiment_name, $subject, $version, "sandpuppy-main-asan", "none");

    # Set AFL_INST_RATIO to 0. We will turn off regular AFL instrumentation completely because we already have an
    # AFL-instrumented version that will be used in the parent fuzzer. The only instrumentation for binaries that will
    # run on child fuzzers will be vvmax, vvperm, or vvhash.
    $ENV{"AFL_INST_RATIO"} = 1;

    # Build a vvmax instrumented version (if we have targets)
    if ($targets->{max}) {
        my $_binary_context = $targets->{max}->{name} . "-asan";
        my $variables_file_argument = "-variables_file=" . $targets->{max}->{variables_file};
        &{$tasks->{build}}($experiment_name, $subject, $version, $_binary_context, "vvmax", $variables_file_argument);
    }

    # Build vvperm instrumented versions (if we have targets)
    foreach my $target (@{$targets->{perm}}) {
        my $_binary_context = $target->{name} . "-asan";
        my $variables_file_argument = "-variables_file=" . $target->{variables_file};
        &{$tasks->{build}}($experiment_name, $subject, $version, $_binary_context, "vvperm", $variables_file_argument);
    }

    # Build vvhash instrumented versions (if we have targets)
    foreach my $target (@{$targets->{hash}}) {
        my $_binary_context = $target->{name} . "-asan";
        my $variables_file_argument = "-variables_file=" . $target->{variables_file};
        &{$tasks->{build}}($experiment_name, $subject, $version, $_binary_context, "vvhash", $variables_file_argument);
    }
}

sub generate_variable_files {
    my $targets = {
        max  => 0,
        perm => [],
        hash => []
    };

    my $variable_targets_file = $_[0];

    my $variable_targets = YAML::XS::LoadFile($variable_targets_file);
    if (scalar @{$variable_targets->{hash}} == 0 &&
        scalar @{$variable_targets->{max}} == 0 &&
        scalar @{$variable_targets->{perm}} == 0) {
        die "No targeted variables in file $variable_targets_file";
    }

    # First we will generate variables files using information from $variable_targets_file. These files will be
    # provided as input to the appropriate LLVM pass in order to generate the instrumented binary.
    if (scalar @{$variable_targets->{max}} > 0) {
        my $vvmax_variables_file = "$workspace/sandpuppy-vvmax-variables.txt";
        $targets->{max} = {
            name           => "sandpuppy-vvmax-" . (scalar @{$variable_targets->{max}}),
            variables_file => $vvmax_variables_file
        };

        open my $VVMAX, ">", $vvmax_variables_file;
        foreach my $variable (@{$variable_targets->{max}}) {
            print $VVMAX $variable . "\n";
        }
        close $VVMAX;
    }

    if (scalar @{$variable_targets->{perm}} > 0) {
        foreach my $variable (@{$variable_targets->{perm}}) {
            my $name = "sandpuppy-vvperm-$variable";
            $name =~ s/\//./g;
            $name =~ s/-\././g;
            my $variables_file = "$workspace/$name.txt";
            push @{$targets->{perm}}, {
                name           => $name,
                variables_file => $variables_file
            };

            open my $VVPERM, ">", $variables_file;
            print $VVPERM "$variable:4\n"; # 4 is amount to shift previous value when calculating permutation key
            close $VVPERM;
        }
    }

    if (scalar @{$variable_targets->{hash}} > 0) {
        foreach my $pair (@{$variable_targets->{hash}}) {
            my $variable1 = $pair->[0];
            my $variable2 = $pair->[1];

            my @components1 = split /:/, $variable1;
            my @components2 = split /:/, $variable2;

            my $name = "sandpuppy-vvhash-$components1[0]:$components1[1]:$components1[2]:$components1[3],$components2[2]:$components2[3]";
            $name =~ s/\//./g;
            $name =~ s/-\././g;
            my $variables_file = "$workspace/$name.txt";
            push @{$targets->{hash}}, {
                name           => $name,
                variables_file => $variables_file
            };

            open my $VVHASH, ">", $variables_file;
            print $VVHASH "$variable1:$components2[2]:$components2[3]\n";
            close $VVHASH;
        }
    }

    return $targets;
}

sub build {
    my $tasks = $subjects->{$subject}->{tasks};
    if (!$tasks) {
        die "No tasks for $subject.";
    }

    if (!$tasks->{build}) {
        die "No build task for $subject.";
    }

    &{$tasks->{build}}($experiment_name, $subject, $version, $binary_context, $waypoints);
}

sub fuzz {
    my $tasks = $subjects->{$subject}->{tasks};
    if (!$tasks) {
        die "No tasks for $subject.";
    }

    if (!$tasks->{fuzz}) {
        die "No fuzz task for $subject.";
    }

    # If the waypoints include vvdump, it means that we are capturing variable-value traces. So we have to start up
    # the trace processor to read in those traces.
    if ($waypoints =~ /vvdump/) {
        $ENV{"__VVD_EXP_NAME"} = $experiment_name;
        $ENV{"__VVD_SUBJECT"} = $full_subject;
        $ENV{"__VVD_BIN_CONTEXT"} = $binary_context;
        $ENV{"__VVD_EXEC_CONTEXT"} = $execution_context;

        pipe my $reader, my $writer;
        $writer->autoflush(1);

        # We are going to start the trace processor. We will start it as a child process and communicate its STDOUT to
        # the parent script.
        my $vvdproc_pid = fork;
        if ($vvdproc_pid) {
            # In the parent process. Here we will start the fuzzer in another child process. The fuzzer STDOUT will
            # still be sent to the parent STDOUT (which we want). Note that after spawning the child fuzzer process
            # we start reading from the trace processor's STDOUT. We do not print anything from it initially as we
            # want to see the fuzzer output. However, if the fuzzer is stopped (Ctrl-C) it sends out a poison pill
            # trace which the trace processor will read. When it does, it will output a message saying "Fuzzer has
            # shut down". Once we detect this string in the trace processor's STDOUT, we will start printing the trace
            # processor output. The trace processor output tells us how many traces from how many processes remain to
            # be inserted into the db.

            close $writer;
            $SIG{INT} = 'IGNORE';

            my $STARTUP_TIME = 10; # about the time it takes to start up vvdproc and the fuzzer
            my $FUZZ_TIME = $subjects->{$subject}->{fuzz_time} + $STARTUP_TIME;
            my $killed = 0;
            my $start_time = time();
            my $fuzzer_pid = &{$tasks->{fuzz}}($experiment_name, $subject, $version, $execution_context, $waypoints, $binary_context, {});
            my $start_printing = 0;
            while (<$reader>) {
                if (!$start_printing) {
                    $start_printing = ($_ =~ /Fuzzer has shut down/);
                }

                if (!$killed and time() - $start_time >= $FUZZ_TIME) {
                    kill 'INT', $fuzzer_pid;
                    $killed = 1;
                }

                print $_ if $start_printing;
            }

            waitpid $vvdproc_pid, 0;

            delete $ENV{"__VVD_EXP_NAME"};
            delete $ENV{"__VVD_SUBJECT"};
            delete $ENV{"__VVD_BIN_CONTEXT"};
            delete $ENV{"__VVD_EXEC_CONTEXT"};
            delete $ENV{"ASAN_OPTIONS"};
        } else {
            # Start the trace processor using open, and redirect its STDOUT to a file handle (using -|). Write the
            # STDOUT content to $writer, which will send it back to the main script. Also make sure we ignore SIGINT
            # because the processor knows to stop on its own (afl-fuzz sends a poison pill in the trace when it is
            # stopped).
            close $reader;
            $SIG{INT} = 'IGNORE';

            chdir "$TOOLS/vvdproc";
            my $vvdproc = "unbuffer mvn package && unbuffer java -Xms1G -Xmx4G -jar target/vvdproc.jar 2>&1";
            open my $vvdproc_output, "-|", $vvdproc;
            while (<$vvdproc_output>) {
                print $writer $_;
            }

            exit;
        }
    } else {
        my $fuzzer_pid = &{$tasks->{fuzz}}($experiment_name, $subject, $version, $execution_context, $waypoints, $binary_context, {});
        waitpid $fuzzer_pid, 0;
    }
}