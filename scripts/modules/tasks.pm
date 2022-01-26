package tasks;

use strict;
use warnings FATAL => 'all';
use Log::Simple::Color;
use File::Path qw(make_path);
use File::stat;
use Time::HiRes qw(time);
use POSIX;
use YAML::XS;
use Data::Dumper;

use vctestbed;
use utils;
use infantheap;
use rarebug;
use maze;
use libpng;
use readelf;
use libtpms;
use smbc;
use cgc;
use dmg2img;
use libtins;

my $log = Log::Simple::Color->new;

my $BASEPATH = glob "~/Projects/phd";
my $TOOLS = "$BASEPATH/tools";

my $WAYPOINTS_NONE = "none";
my $SANDPUPPY_MAIN_TARGET_NAME = "sandpuppy-main";
my $SANDPUPPY_SYNC_DIRECTORY = "sandpuppy-sync";

my $subjects = {
    vctestbed  => {
        binary_name => "vctestbed",
        tasks       => {
            build            => \&vctestbed::build,
            fuzz             => create_fuzz_task(\&vctestbed::get_fuzz_command),
            pod_fuzz_command => create_pod_fuzz_command_task(\&vctestbed::get_fuzz_command)
        },
        fuzz_time   => 300
    },
    infantheap  => {
        binary_name => "infantheap",
        tasks       => {
            build            => \&infantheap::build,
            fuzz             => create_fuzz_task(\&infantheap::get_fuzz_command),
            pod_fuzz_command => create_pod_fuzz_command_task(\&infantheap::get_fuzz_command)
        },
        fuzz_time   => 600
    },
    rarebug     => {
        binary_name => "rarebug",
        tasks       => {
            build            => \&rarebug::build,
            fuzz             => create_fuzz_task(\&rarebug::get_fuzz_command),
            pod_fuzz_command => create_pod_fuzz_command_task(\&rarebug::get_fuzz_command)
        },
        fuzz_time   => 600
    },
    maze        => {
        binary_name => "maze",
        source_name => "maze.c",
        tasks       => {
            build            => \&maze::build,
            fuzz             => create_fuzz_task(\&maze::get_fuzz_command),
            pod_fuzz_command => create_pod_fuzz_command_task(\&maze::get_fuzz_command)
        },
        fuzz_time   => 360
    },
    maze_ijon   => {
        binary_name => "maze_ijon",
        source_name => "maze_ijon.c",
        tasks       => {
            build            => \&maze::build,
            fuzz             => create_fuzz_task(\&maze::get_fuzz_command),
            pod_fuzz_command => create_pod_fuzz_command_task(\&maze::get_fuzz_command)
        },
        fuzz_time   => 360
    },
    maze_klee   => {
        binary_name => "maze_klee",
        source_name => "maze_klee.c",
        tasks       => {
            build            => \&maze::build,
            fuzz             => create_fuzz_task(\&maze::get_fuzz_command),
            pod_fuzz_command => create_pod_fuzz_command_task(\&maze::get_fuzz_command)
        },
        fuzz_time   => 360
    },
    libpng      => {
        binary_name => "readpng",
        tasks       => {
            build            => \&libpng::build,
            fuzz             => create_fuzz_task(\&libpng::get_fuzz_command),
            pod_fuzz_command => create_pod_fuzz_command_task(\&libpng::get_fuzz_command)
        },
        fuzz_time   => 900
    },
    readelf     => {
        binary_name => "readelf",
        tasks       => {
            build            => \&readelf::build,
            fuzz             => create_fuzz_task(\&readelf::get_fuzz_command),
            pod_fuzz_command => create_pod_fuzz_command_task(\&readelf::get_fuzz_command)
        },
        fuzz_time   => 600
    },
    libtpms     => {
        binary_name => "readtpmc",
        tasks       => {
            build            => \&libtpms::build,
            fuzz             => create_fuzz_task(\&libtpms::get_fuzz_command),
            pod_fuzz_command => create_pod_fuzz_command_task(\&libtpms::get_fuzz_command)
        },
        fuzz_time   => 600
    },
    smbc        => {
        binary_name => "smbc",
        tasks       => {
            build            => \&smbc::build,
            fuzz             => create_fuzz_task(\&smbc::get_fuzz_command),
            pod_fuzz_command => create_pod_fuzz_command_task(\&smbc::get_fuzz_command)
        },
        fuzz_time   => 360
    },
    hawaii_sets => {
        binary_name => "hawaii_sets",
        tasks       => {
            build            => \&cgc::build,
            fuzz             => create_fuzz_task(\&cgc::get_fuzz_command),
            pod_fuzz_command => create_pod_fuzz_command_task(\&cgc::get_fuzz_command)
        },
        fuzz_time   => 600
    },
    dmg2img     => {
        binary_name => "dmg2img",
        tasks       => {
            build            => \&dmg2img::build,
            fuzz             => create_fuzz_task(\&dmg2img::get_fuzz_command),
            pod_fuzz_command => create_pod_fuzz_command_task(\&dmg2img::get_fuzz_command)
        },
        fuzz_time   => 360
    },
    libtins     => {
        binary_name => "readpcap",
        tasks       => {
            build            => \&libtins::build,
            fuzz             => create_fuzz_task(\&libtins::get_fuzz_command),
            pod_fuzz_command => create_pod_fuzz_command_task(\&libtins::get_fuzz_command)
        },
        fuzz_time   => 360
    }
};

sub create_pod_fuzz_command_task {
    my $get_fuzz_command = $_[0];

    return sub {
        my $experiment_name = $_[0];
        my $subject = $_[1];
        my $version = $_[2];
        my $waypoints = $_[3];
        my $binary_context = $_[4];
        my $execution_context = $_[5];
        my $options = utils::merge($_[6], {
            binary_name       => $subjects->{$subject}->{binary_name},
            use_asan          => $binary_context =~ /-asan$|-asan-/ ? 1 : 0,
            non_deterministic => $execution_context =~ /-non-det$|-non-det-/ ? 1 : 0,
            use_kubernetes    => 1
        });
        my ($fuzz_command, $ENV_VARS) = $get_fuzz_command->(
            $experiment_name,
            $subject,
            $version,
            $waypoints,
            $binary_context,
            $execution_context,
            $options
        );

        my $command = "env";
        foreach my $ENV_VAR (keys(%{$ENV_VARS})) {
            $command .= " $ENV_VAR=$ENV_VARS->{$ENV_VAR}";
        }

        return "$command $fuzz_command";
    }
}

sub create_fuzz_task {
    my $get_fuzz_command = $_[0];

    return sub {
        my $experiment_name = $_[0];
        my $subject = $_[1];
        my $version = $_[2];
        my $waypoints = $_[3];
        my $binary_context = $_[4];
        my $execution_context = $_[5];
        my $options = utils::merge($_[6], {
            binary_name       => $subjects->{$subject}->{binary_name},
            use_asan          => $binary_context =~ /-asan$|-asan-/ ? 1 : 0,
            non_deterministic => $execution_context =~ /-non-det$|-non-det-/ ? 1 : 0,
        });
        my ($fuzz_command, $ENV_VARS) = $get_fuzz_command->(
            $experiment_name,
            $subject,
            $version,
            $waypoints,
            $binary_context,
            $execution_context,
            $options
        );
        # print(">>>> $fuzz_command <<<<\n");

        my $pid = fork;
        return $pid if $pid;

        foreach my $ENV_VAR (keys(%{$ENV_VARS})) {
            $ENV{$ENV_VAR} = $ENV_VARS->{$ENV_VAR};
        }

        if ($options->{async}) {
            # If async fuzzing is requested redirect STDOUT and STDERR to /dev/null.
            open STDOUT, ">>",  "/tmp/errs" or die "$0: open: $!";
            open STDERR, ">&", \*STDOUT    or exit 1;
        }

        # Need to run in shell using exec otherwise it runs it as sh -c $fuzz_command and the pid we get is of sh. So
        # when we try to kill it, it doesn't work.
        exec "exec $fuzz_command";
    }
}

sub initialize_workspace {
    my $experiment_name = $_[0];
    my $subject = $_[1];
    my $version = $_[2];

    if (!$subjects->{$subject}) {
        die "No subject named $subject";
    }

    my $workspace = utils::get_workspace($experiment_name, $subject, $version);
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
}

sub subject_exists {
    return $subjects->{$_[0]};
}

sub subject_has_task {
    return $subjects->{$_[0]}->{tasks}->{$_[1]};
}

sub build {
    my $experiment_name = $_[0];
    my $subject = $_[1];
    my $version = $_[2];
    my $waypoints = $_[3];
    my $binary_context = $_[4];
    my $options = $_[5];
    if ($options->{backup} && $options->{use_existing}) {
        die "Both backup and use_existing cannot be set";
    }

    my $workspace = utils::get_workspace($experiment_name, $subject, $version);
    my $binary = "$workspace/binaries/$binary_context/$subjects->{$subject}->{binary_name}";

    my $build_anyway = 0;
    if ($options->{use_existing} && ! -e $binary) {
        $log->warning("use_existing is set, but cannot find a binary at $binary, so building it");
        $build_anyway = 1;
    }

    if (!$options->{use_existing} || $build_anyway) {
        if (defined $subjects->{$subject}->{binary_name} && defined $subjects->{$subject}->{source_name}) {
            $options->{binary_name} = $subjects->{$subject}->{binary_name};
            $options->{source_name} = $subjects->{$subject}->{source_name};
        }

        my $tasks = $subjects->{$subject}->{tasks};
        $tasks->{build}->($experiment_name, $subject, $version, $waypoints, $binary_context, $options);

        chdir $BASEPATH;
    }
}

sub fuzz {
    my $subject = $_[1];
    my $options = $_[6];

    my $tasks = $subjects->{$subject}->{tasks};
    my $fuzzer_pid = $tasks->{fuzz}->(@_);
    if ($options->{async}) {
        return $fuzzer_pid;
    }

    waitpid $fuzzer_pid, 0;
}

sub pod_fuzz_command {
    my $subject = $_[1];

    my $tasks = $subjects->{$subject}->{tasks};
    return $tasks->{pod_fuzz_command}->(@_);
}

sub setup_named_pipe {
    my $NAMED_PIPE = "/tmp/vvdump";
    if (!-e $NAMED_PIPE) {
        $log->info("Creating named pipe at $NAMED_PIPE");
        POSIX::mkfifo($NAMED_PIPE, 0700) or die "Could not create $NAMED_PIPE";
    }

    # Increase maximum named-pipe size and set the size of our pipe. It appears the maximum possible size is 32 mb; at least
    # on my system.
    my $NAMED_PIPE_SIZE = 1048576 * 32;
    my $pid = fork;
    if (!$pid) {
        open my $f, ">", $NAMED_PIPE;
        while(1) { }
        exit;
    } else {
        # Need sudo to increase the maximum pipe size. Make sure there is an entry like the following in the sudoers
        # file:
        # myuser  ALL=(ALL:ALL) NOPASSWD:/sbin/sysctl fs.pipe-max-size=*
        system("sudo sysctl fs.pipe-max-size=$NAMED_PIPE_SIZE");
        open FD, $NAMED_PIPE  or die "Cannot open $NAMED_PIPE";
        my $old_size = fcntl(\*FD, Fcntl::F_GETPIPE_SZ, 0);
        $log->info("Old pipe size: $old_size");

        fcntl(\*FD, Fcntl::F_SETPIPE_SZ, int($NAMED_PIPE_SIZE));
        my $new_size = fcntl(\*FD, Fcntl::F_GETPIPE_SZ, 0);
        if ($new_size < $NAMED_PIPE_SIZE) {
            $log->error("Failed setting pipe size to $NAMED_PIPE_SIZE");
        } else {
            $log->info("New pipe size: $new_size");
        }

        kill 'INT', $pid;
    }
}

sub vvdump_fuzz {
    my $experiment_name = $_[0];
    my $subject = $_[1];
    my $version = $_[2];
    my $waypoints = $_[3];
    my $binary_context = $_[4];
    my $execution_context = $_[5];
    my $options = $_[6];

    setup_named_pipe();

    my $tasks = $subjects->{$subject}->{tasks};

    if ($options->{async}) {
        $log->warning("Ignoring request for asynchronous fuzzing because waypoints include vvdump.");
        $options->{async} = 0;
    }

    $ENV{"__VVD_EXP_NAME"} = $experiment_name;
    $ENV{"__VVD_SUBJECT"} = $version ? "$subject-$version" : $subject;
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

        my $SLEEP_TIME = 10;
        my $STARTUP_TIME = 5; # about the time it takes to start up vvdproc and the fuzzer
        my $FUZZ_TIME = $subjects->{$subject}->{fuzz_time} + $STARTUP_TIME;
        my $killed = 0;

        $| = 1;

        print "Waiting ${SLEEP_TIME}s for trace processor to be ready...";
        sleep $SLEEP_TIME;

        my $start_time = time();

        # If parallel fuzzing is requested during trace generation we are going to start a parent fuzzer and a child
        # fuzzer.
        my $fuzzer_pid = $tasks->{fuzz}->(
            $experiment_name,
            $subject,
            $version,
            $waypoints,
            $binary_context,
            $execution_context,
            {
                exit_when_done => 1,
                resume         => $options->{resume}
            }
        );

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
        #my $vvdproc = "unbuffer mvn package && unbuffer java -agentpath:/home/vivin/jprofiler12/bin/linux-x64/libjprofilerti.so=port=8849 -Xms1G -Xmx4G -jar target/vvdproc.jar 2>&1";
        my $vvdproc = "unbuffer mvn package && unbuffer java -Xms8G -Xmx16G -jar target/vvdproc.jar 2>&1";
        open my $vvdproc_output, "-|", $vvdproc;
        while (<$vvdproc_output>) {
            print $writer $_;
        }

        exit;
    }
}

sub sandpuppy_vanilla_fuzz {
    my $experiment_name = $_[0];
    my $subject = $_[1];
    my $version = $_[2];
    my $options = $_[3];

    # Build main target. This is just vanilla AFL instrumentation.
    my $main_target = {
        id                => "vanilla-$SANDPUPPY_MAIN_TARGET_NAME",
        name              => "vanilla-$SANDPUPPY_MAIN_TARGET_NAME",
        experiment_name   => $experiment_name,
        subject           => $subject,
        version           => $version,
        waypoints         => $WAYPOINTS_NONE,
        binary_context    => $SANDPUPPY_MAIN_TARGET_NAME . ($options->{use_asan} ? "-asan" : ""),
        execution_context => $SANDPUPPY_MAIN_TARGET_NAME . ($options->{use_asan} ? "-asan" : "")
    };
    build(
        $experiment_name,
        $subject,
        $version,
        $main_target->{waypoints},
        $main_target->{binary_context},
        { use_existing => 1, backup => 0, m32 => $options->{use_asan} }
    );

    my $full_subject = $subject . ($version ? "-$version" : "");
    my $run_name = $options->{run_name};

    my $id_to_pod_name_and_target = {};

    $log->info("Vanilla AFL fuzzing using kubernetes requested.\n");

    my $workspace = utils::get_workspace($experiment_name, $subject, $version);
    my $subject_directory = utils::get_subject_directory($experiment_name, $subject, $version);
    my $local_nfs_subject_directory = "/mnt/vivin-nfs/vivin/$subject_directory";
    my $container_nfs_subject_directory = "/private-nfs/vivin/$subject_directory";

    if (! -d $local_nfs_subject_directory) {
        system("mkdir -p $local_nfs_subject_directory");
    }

    if (! -d "$local_nfs_subject_directory/results/$run_name") {
        system("mkdir -p $local_nfs_subject_directory/results/$run_name");
    }

    if (! -d "$local_nfs_subject_directory/binaries") {
        system("mkdir $local_nfs_subject_directory/binaries");
    }

    my $main_target_binary_dir = $main_target->{binary_context};
    if (! -e -d "$local_nfs_subject_directory/binaries/$main_target_binary_dir") {
        system("mkdir $local_nfs_subject_directory/binaries/$main_target_binary_dir");
    }

    my @main_target_files = `find "$workspace/binaries/$main_target_binary_dir" -type f | sed -e 's,^.*/,,'`;
    foreach my $main_target_file (@main_target_files) {
        chomp($main_target_file);

        my $local_file_path = "$workspace/binaries/$main_target_binary_dir/$main_target_file";
        my $nfs_file_path = "$local_nfs_subject_directory/binaries/$main_target_binary_dir/$main_target_file";

        if (-e -f $nfs_file_path) {
            my $ctime_local_file = stat($local_file_path)->ctime;
            my $ctime_nfs_file = stat($nfs_file_path)->ctime;

            if ($ctime_nfs_file >= $ctime_local_file) {
                $log->info("Not copying $main_target_binary_dir/$main_target_file because newer version exists on NFS.");
            } else {
                $log->info("Copying $main_target_binary_dir/$main_target_file to NFS as it is newer than the existing one.");
                system("cp $local_file_path $nfs_file_path")
            }
        } else {
            $log->info("Copying $main_target_binary_dir/$main_target_file to NFS.");
            system("cp $local_file_path $nfs_file_path")
        }
    }

    my $pod_name = "$experiment_name-$full_subject-$run_name--$main_target->{id}" . ($options->{use_asan} ? "-asan" : "");
    $pod_name =~ s/[\._]/-/g; # pod names have restrictions

    $id_to_pod_name_and_target->{$main_target->{id}} = {
        pod_name    => $pod_name,
        target_name => $main_target->{name}
    };

    $log->info("Creating target script for main target...");
    my $target_script = utils::generate_single_target_script(
        $experiment_name,
        $subject,
        $version,
        $pod_name,
        $main_target,
        $options,
        pod_fuzz_command(
            $experiment_name,
            $subject,
            $version,
            $main_target->{waypoints},
            $main_target->{binary_context},
            $main_target->{execution_context},
            {
                async              => 1,
                fuzzer_id          => $main_target->{id},
                parallel_fuzz_mode => "parent",
                resume             => 0
            }
        ),
        pod_fuzz_command(
            $experiment_name,
            $subject,
            $version,
            $main_target->{waypoints},
            $main_target->{binary_context},
            $main_target->{execution_context},
            {
                async              => 1,
                fuzzer_id          => $main_target->{id},
                parallel_fuzz_mode => "parent",
                resume             => 1
            }
        )
    );

    #if (! -f "$local_nfs_workspace/$main_target->{id}") {
    open my $TARGET_SCRIPT, ">", "$local_nfs_subject_directory/$main_target->{id}";
    print $TARGET_SCRIPT $target_script;
    close $TARGET_SCRIPT;
    #}

    system "chmod 755 $local_nfs_subject_directory/$main_target->{id}";

    print "\n";

    my $pod_command = "$container_nfs_subject_directory/$main_target->{id} $run_name" . ($options->{resume} ? " resume" : "");
    my $pod_create_command = "kuboid/scripts/pod_create -n \"$pod_name\" -s /tmp/sandpuppy.existing -i vivin/sandpuppy $pod_command";

    $log->info("Preparing to create and run kubernetes pod for target...");

    my $id_to_pod_name_and_target_file = "$local_nfs_subject_directory/results/$run_name/id_to_pod_name_and_target.yml";
    YAML::XS::DumpFile($id_to_pod_name_and_target_file, $id_to_pod_name_and_target);

    #if (1) {
    #    exit(0);
    #}

    $log->info("Creating pod $pod_name for target $main_target->{id}");
    system ($pod_create_command);
    if ($? != 0) {
        print "Creating pod failed: $!\n";
    }
}

sub sandpuppy_fuzz {
    my $experiment_name = $_[0];
    my $subject = $_[1];
    my $version = $_[2];
    my $options = $_[3];

    # Generate variables files and build targets using the output from the analysis phase (which should be stored
    # under the results for the provided execution_context). The analysis phase identifies interesting variables to
    # instrument, so we will build targets that do just that.
    my ($main_target, $targets) = build_sandpuppy_targets(
        $experiment_name,
        $subject,
        $version,
        $options
    );

    my $num_targets = scalar @{$targets} + 1; # Account for main target

    my $full_subject = $subject . ($version ? "-$version" : "");
    my $run_name = $options->{run_name};

    my $id_to_pod_name_and_target = {};
    my $pod_name_to_create_command = {};

    $log->info("Fuzzing using kubernetes requested.\n");

    my $workspace = utils::get_workspace($experiment_name, $subject, $version);
    my $subject_directory = utils::get_subject_directory($experiment_name, $subject, $version);
    my $local_nfs_subject_directory = "/mnt/vivin-nfs/vivin/$subject_directory";
    my $container_nfs_subject_directory = "/private-nfs/vivin/$subject_directory";

    if (! -d $local_nfs_subject_directory) {
        system("mkdir -p $local_nfs_subject_directory");
    }

    if (! -d "$local_nfs_subject_directory/results/$run_name") {
        system("mkdir -p $local_nfs_subject_directory/results/$run_name");
    }

    if (! -d "$local_nfs_subject_directory/binaries") {
        system("mkdir $local_nfs_subject_directory/binaries");
    }

    my $main_target_binary_dir = $main_target->{binary_context};
    if (! -e -d "$local_nfs_subject_directory/binaries/$main_target_binary_dir") {
        system("mkdir $local_nfs_subject_directory/binaries/$main_target_binary_dir");
    }

    my @main_target_files = `find "$workspace/binaries/$main_target_binary_dir" -type f | sed -e 's,^.*/,,'`;
    foreach my $main_target_file (@main_target_files) {
        chomp($main_target_file);

        my $local_file_path = "$workspace/binaries/$main_target_binary_dir/$main_target_file";
        my $nfs_file_path = "$local_nfs_subject_directory/binaries/$main_target_binary_dir/$main_target_file";

        if (-e -f $nfs_file_path) {
            my $ctime_local_file = stat($local_file_path)->ctime;
            my $ctime_nfs_file = stat($nfs_file_path)->ctime;

            if ($ctime_nfs_file >= $ctime_local_file) {
                $log->info("[1/$num_targets] Not copying $main_target_binary_dir/$main_target_file because newer version exists on NFS.");
            } else {
                $log->info("[1/$num_targets] Copying $main_target_binary_dir/$main_target_file to NFS as it is newer than the existing one.");
                system("cp $local_file_path $nfs_file_path")
            }
        } else {
            $log->info("[1/$num_targets] Copying $main_target_binary_dir/$main_target_file to NFS.");
            system("cp $local_file_path $nfs_file_path")
        }
    }

    my $pod_name = "$experiment_name-$full_subject-$run_name--$main_target->{id}" . ($options->{use_asan} ? "-asan" : "");
    $pod_name =~ s/[\._]/-/g; # pod names have restrictions

    $id_to_pod_name_and_target->{$main_target->{id}} = {
        pod_name    => $pod_name,
        target_name => $main_target->{name}
    };

    $log->info("[1/$num_targets] Creating target script for main target...");
    my $target_script = utils::generate_target_script(
        $experiment_name,
        $subject,
        $version,
        $pod_name,
        $main_target,
        $options,
        pod_fuzz_command(
            $experiment_name,
            $subject,
            $version,
            $main_target->{waypoints},
            $main_target->{binary_context},
            $main_target->{execution_context},
            {
                async              => 1,
                fuzzer_id          => $main_target->{id},
                parallel_fuzz_mode => "parent",
                resume             => 0
            }
        ),
        pod_fuzz_command(
            $experiment_name,
            $subject,
            $version,
            $main_target->{waypoints},
            $main_target->{binary_context},
            $main_target->{execution_context},
            {
                async              => 1,
                fuzzer_id          => $main_target->{id},
                parallel_fuzz_mode => "parent",
                resume             => 1
            }
        )
    );

    #if (! -f "$local_nfs_workspace/$main_target->{id}") {
        open my $TARGET_SCRIPT, ">", "$local_nfs_subject_directory/$main_target->{id}";
        print $TARGET_SCRIPT $target_script;
        close $TARGET_SCRIPT;
    #}

    system "chmod 755 $local_nfs_subject_directory/$main_target->{id}";

    print "\n";

    my $pod_command = "$container_nfs_subject_directory/$main_target->{id} $run_name" . ($options->{resume} ? " resume" : "");
    $pod_name_to_create_command->{$pod_name} = {
        target   => $main_target->{id},
        command  => "kuboid/scripts/pod_create -n \"$pod_name\" -s /tmp/sandpuppy.existing -i vivin/sandpuppy $pod_command",
        sort_key => "a" # so that it always shows up first
    };

    my $i = 2; # Account for main target
    foreach my $target (@{$targets}) {
        my $target_binary_dir = $target->{binary_context};
        if (! -e -d "$local_nfs_subject_directory/binaries/$target_binary_dir") {
            system("mkdir $local_nfs_subject_directory/binaries/$target_binary_dir");
        }

        my @target_files = `find "$workspace/binaries/$target_binary_dir" -type f | sed -e 's,^.*/,,'`;
        foreach my $target_file (@target_files) {
            chomp($target_file);

            my $local_file_path = "$workspace/binaries/$target_binary_dir/$target_file";
            my $nfs_file_path = "$local_nfs_subject_directory/binaries/$target_binary_dir/$target_file";

            if (-e -f $nfs_file_path) {
                my $ctime_local_file = stat($local_file_path)->ctime;
                my $ctime_nfs_file = stat($nfs_file_path)->ctime;

                if ($ctime_nfs_file >= $ctime_local_file) {
                    $log->info("[$i/$num_targets] Not copying $target_binary_dir/$target_file because it already exists on NFS and is newer.");
                } else {
                    $log->info("[$i/$num_targets] Copying $target_binary_dir/$target_file to NFS as it is newer than the existing one..");
                    system("cp $local_file_path $nfs_file_path")
                }
            } else {
                $log->info("[$i/$num_targets] Copying $target_binary_dir/$target_file to NFS.");
                system("cp $local_file_path $nfs_file_path")
            }
        }

        my $asan_suffix = ($options->{use_asan} ? "-asan" : "");
        $pod_name = $target->{waypoints} eq "vvmax" ?
            "$experiment_name-$full_subject-$run_name--$target->{id}$asan_suffix" :
            "$experiment_name-$full_subject-$run_name--$target->{id}-$target->{waypoints}$asan_suffix";
        $pod_name =~ s/[\._]/-/g; # pod names have restrictions

        $id_to_pod_name_and_target->{$target->{id}} = {
            pod_name    => $pod_name,
            target_name => $target->{name}
        };

        $log->info("[$i/$num_targets] Creating target script for $target->{name}...");
        $target_script = utils::generate_target_script(
            $experiment_name,
            $subject,
            $version,
            $pod_name,
            $target,
            $options,
            pod_fuzz_command(
                $experiment_name,
                $subject,
                $version,
                $target->{waypoints},
                $target->{binary_context},
                $target->{execution_context},
                {
                    async              => 1,
                    fuzzer_id          => $target->{id},
                    parallel_fuzz_mode => "child",
                    resume             => 0
                    #exit_when_done      => 1
                }
            ),
            pod_fuzz_command(
                $experiment_name,
                $subject,
                $version,
                $target->{waypoints},
                $target->{binary_context},
                $target->{execution_context},
                {
                    async              => 1,
                    fuzzer_id          => $target->{id},
                    parallel_fuzz_mode => "child",
                    resume             => 1
                    #exit_when_done      => 1
                }
            )
        );

        #if (! -f "$local_nfs_workspace/$target->{id}") {
            open $TARGET_SCRIPT, ">", "$local_nfs_subject_directory/$target->{id}";
            print $TARGET_SCRIPT $target_script;
            close $TARGET_SCRIPT;

            system "chmod 755 $local_nfs_subject_directory/$target->{id}";
        #}

        $pod_command = "$container_nfs_subject_directory/$target->{id} $run_name" . ($options->{resume} ? " resume" : "");
        $pod_name_to_create_command->{$pod_name} = {
            target   => $target->{id},
            command  => "kuboid/scripts/pod_create -n \"$pod_name\" -s /tmp/sandpuppy.existing -i vivin/sandpuppy $pod_command",
            sort_key => $target->{name}
        };

        print "\n";
        $i++;
    }

    $log->info("Preparing to create and run kubernetes pods for targets...");

    my $id_to_pod_name_and_target_file = "$local_nfs_subject_directory/results/$run_name/id_to_pod_name_and_target.yml";
    YAML::XS::DumpFile($id_to_pod_name_and_target_file, $id_to_pod_name_and_target);

    #if (1) {
    #    exit(0);
    #}

    $log->info("Getting list of existing pods (so that we don't recreate)...");
    system ("kuboid/scripts/pod_names > /tmp/sandpuppy.existing");

    my $existing_pods = 0;
    $i = 1;
    foreach $pod_name (sort { $pod_name_to_create_command->{$a}->{sort_key} cmp $pod_name_to_create_command->{$b}->{sort_key} } keys %{$pod_name_to_create_command}) {
        my $target = $pod_name_to_create_command->{$pod_name}->{target};
        my $command = $pod_name_to_create_command->{$pod_name}->{command};

        # Check to see if the pod already exists. If it does, we don't want to create it
        system("kubectl get pod $pod_name >/dev/null 2>&1");
        if ($? != 0) {
            $log->info("[$i/$num_targets] Creating pod $pod_name for target $target");
            system ($command);
            if ($? != 0) {
                print "[$i/$num_targets] Creating pod failed: $!\n";
            }
        } else {
            $log->info("[$i/$num_targets] Skipping existing pod $pod_name for target $target");
            $existing_pods++;
        }

        print "\n";

        $i++;
    }

    my $requested_pods = (scalar @{$targets} + 1) - $existing_pods;
    my $num_finished = 0;
    until ($num_finished == $requested_pods) {
        my $status_counts = {};
        map {
            chomp;
            $status_counts->{$_} = defined $status_counts->{$_} ? $status_counts->{$_} + 1 : 1;
        } `kubectl get pods --no-headers | grep -vf /tmp/sandpuppy.existing | awk '{ print \$3; }'`;

        print "Requested pods: $requested_pods\n";
        foreach my $status (sort(keys(%{$status_counts}))) {
            print "  $status: $status_counts->{$status}\n";
        }

        print "\n";

        my $num_error = defined $status_counts->{Error} ? $status_counts->{Error} : 0;
        my $num_running = defined $status_counts->{Running} ? $status_counts->{Running} : 0;
        $num_finished = $num_error + $num_running;

        sleep 2;
    }
}

sub build_sandpuppy_targets {
    my $experiment_name = $_[0];
    my $subject = $_[1];
    my $version = $_[2];
    my $options = $_[3];

    my $workspace = utils::get_workspace($experiment_name, $subject, $version);
    my $results_dir = "$workspace/results";
    if (! -d $results_dir) {
        die "Could not find results directory $results_dir to use for sandpuppy fuzzing.";
    }

    my $interesting_variables_file = "$results_dir/sandpuppy_interesting_variables.yml";
    if (! -e $interesting_variables_file) {
        die "Could not find interesting variables file $interesting_variables_file to use for sandpuppy fuzzing.";
    }

    # First build main target
    my $main_target = {
        id                => $SANDPUPPY_MAIN_TARGET_NAME,
        name              => $SANDPUPPY_MAIN_TARGET_NAME,
        experiment_name   => $experiment_name,
        subject           => $subject,
        version           => $version,
        waypoints         => $WAYPOINTS_NONE,
        binary_context    => $SANDPUPPY_MAIN_TARGET_NAME . ($options->{use_asan} ? "-asan" : ""),
        execution_context => $SANDPUPPY_MAIN_TARGET_NAME . ($options->{use_asan} ? "-asan" : "")
    };
    build(
        $experiment_name,
        $subject,
        $version,
        $main_target->{waypoints},
        $main_target->{binary_context},
        { use_existing => 1, backup => 0, m32 => $options->{use_asan} }
    );

    my $name_to_id = {};
    my $name_to_id_file = "$results_dir/sandpuppy-target-name-to-id.yml";
    if (-e $name_to_id_file) {
        $name_to_id = YAML::XS::LoadFile($name_to_id_file);
    }

    my $grouped_targets = {
        max  => 0,
        perm => [],
        hash => [],
        max2 => []
    };

    my $interesting_variables = YAML::XS::LoadFile($interesting_variables_file);
    if (scalar @{$interesting_variables->{hash}} == 0 &&
        scalar @{$interesting_variables->{max}} == 0 &&
        scalar @{$interesting_variables->{perm}} == 0) {
        die "No targeted variables in file $interesting_variables_file";
    }

    # First we will generate variables files using information from $interesting_variables_file. These files will be
    # provided as input to the appropriate LLVM pass in order to generate the instrumented binary.
    if (scalar @{$interesting_variables->{max}} > 0) {
        my $name = "sandpuppy-vvmax-" . (scalar @{$interesting_variables->{max}});
        my $id = $name;
        my $vvmax_variables_file = "$results_dir/sandpuppy-vvmax-variables.txt";
        $grouped_targets->{max} = {
            id                => $id,
            name              => $name,
            experiment_name   => $experiment_name,
            subject           => $subject,
            version           => $version,
            waypoints         => "vvmax",
            binary_context    => $name . ($options->{use_asan} ? "-asan" : ""),
            execution_context => $name . ($options->{use_asan} ? "-asan" : ""),
            variables_file    => $vvmax_variables_file
        };

        $name_to_id->{$name} = $id if !$name_to_id->{$name};

        open my $VVMAX, ">", $vvmax_variables_file;
        foreach my $variable (@{$interesting_variables->{max}}) {
            print $VVMAX $variable . "\n";
        }
        close $VVMAX;
    }

    if (scalar @{$interesting_variables->{perm}} > 0) {
        foreach my $variable_entry (@{$interesting_variables->{perm}}) {

            my $variable = $variable_entry->{variable};
            my $max_value = $variable_entry->{max};
            my $min_value = $variable_entry->{min};
            my $shift_width = 8;

            # If value never goes above 15 (F), we can shift by 4 bits instead of 8; lets us track more permutations.
            if ($min_value >= 0 && $max_value <= 15) {
                $shift_width = 4;
            }

            my $name = "sandpuppy-vvperm-$variable:sw:$shift_width";
            $name =~ s/\//./g;
            $name =~ s/-\././g;
            my $id = $name_to_id->{$name} ? $name_to_id->{$name} : utils::get_random_fuzzer_id();
            my $variables_file = "$results_dir/$name.txt";
            push @{$grouped_targets->{perm}}, {
                id                => $id,
                name              => $name,
                experiment_name   => $experiment_name,
                subject           => $subject,
                version           => $version,
                waypoints         => "vvperm",
                binary_context    => $name . ($options->{use_asan} ? "-asan" : ""),
                execution_context => $name . ($options->{use_asan} ? "-asan" : ""),
                variables_file    => $variables_file
            };

            $name_to_id->{$name} = $id if !$name_to_id->{$name};

            open my $VVPERM, ">", $variables_file;
            print $VVPERM "$variable:$shift_width\n";
            close $VVPERM;
        }
    }

    if (scalar @{$interesting_variables->{hash}} > 0) {
        foreach my $pair (@{$interesting_variables->{hash}}) {
            my @sorted_pair = sort @{$pair};
            my $variable1 = $sorted_pair[0];
            my $variable2 = $sorted_pair[1];

            my @components1 = split /:/, $variable1;
            my @components2 = split /:/, $variable2;

            my $filename = $components1[0];
            my $function = $components1[1];

            my $variable1Name = $components1[2];
            my $variable1Line = $components1[3];
            my $variable2Name = $components2[2];
            my $variable2Line = $components2[3];

            my $name = "sandpuppy-vvhash-$filename:$function:$variable1Name:$variable1Line,$variable2Name:$variable2Line";
            $name =~ s/\//./g;
            $name =~ s/-\././g;
            my $id = $name_to_id->{$name} ? $name_to_id->{$name} : utils::get_random_fuzzer_id();
            my $variables_file = "$results_dir/$name.txt";
            push @{$grouped_targets->{hash}}, {
                id                => $id,
                name              => $name,
                experiment_name   => $experiment_name,
                subject           => $subject,
                version           => $version,
                waypoints         => "vvhash",
                binary_context    => $name . ($options->{use_asan} ? "-asan" : ""),
                execution_context => $name . ($options->{use_asan} ? "-asan" : ""),
                variables_file    => $variables_file
            };

            $name_to_id->{$name} = $id if !$name_to_id->{$name};

            open my $VVHASH, ">", $variables_file;
            print $VVHASH "$filename:$function:$variable1Name:$variable1Line:$variable2Name:$variable2Line\n";
            close $VVHASH;
        }
    }

    if (scalar @{$interesting_variables->{max2}} > 0) {
        foreach my $variables_entry (@{$interesting_variables->{max2}}) {

            my $first_variable = $variables_entry->{first_variable};
            my $second_variable = $variables_entry->{second_variable};
            my $second_min = $variables_entry->{second_min};
            my $second_max = $variables_entry->{second_max};
            foreach my $slot_size (1, 4, 8, 16, 32, 64) {
                # If both the maximum and minimum values of the second variable end up being in the same slot, let's
                # skip this pair because it's no different than maximizing the first variable by itself.
                next if (int $second_min / $slot_size) == (int $second_max / $slot_size);

                my @components1 = split /:/, $first_variable;
                my @components2 = split /:/, $second_variable;

                my $filename = $components1[0];
                my $function = $components1[1];

                my $variable1Name = $components1[2];
                my $variable1Line = $components1[3];
                my $variable2Name = $components2[2];
                my $variable2Line = $components2[3];

                my $name = "sandpuppy-vvmax2-$filename:$function:$variable1Name:$variable1Line,$variable2Name:$variable2Line:ssz:$slot_size";
                $name =~ s/\//./g;
                $name =~ s/-\././g;
                my $id = $name_to_id->{$name} ? $name_to_id->{$name} : utils::get_random_fuzzer_id();
                my $variables_file = "$results_dir/$name.txt";
                push @{$grouped_targets->{max2}}, {
                    id                => $id,
                    name              => $name,
                    experiment_name   => $experiment_name,
                    subject           => $subject,
                    version           => $version,
                    waypoints         => "vvmax2",
                    binary_context    => $name . ($options->{use_asan} ? "-asan" : ""),
                    execution_context => $name . ($options->{use_asan} ? "-asan" : ""),
                    variables_file    => $variables_file
                };

                $name_to_id->{$name} = $id if !$name_to_id->{$name};

                open my $VVHASH, ">", $variables_file;
                print $VVHASH "$filename:$function:$variable1Name:$variable1Line:$variable2Name:$variable2Line:$slot_size\n";
                close $VVHASH;
            }
        }
    }

    # Set AFL_INST_RATIO to 1. We will turn off regular AFL instrumentation completely because we already have an
    # AFL-instrumented version that will be used in the parent fuzzer. The only instrumentation for binaries that will
    # be fuzzed on child fuzzers will be vvmax, vvperm, or vvhash depending on what variables were identified as
    # interesting.
    # $ENV{"AFL_INST_RATIO"} = 1;

    # We will combine all the grouped targets above into a single array. We interleave vvperm and vvhash targets just
    # so that when we fuzz, both groups get a chance at the beginning, as we have a limited number of cores. There is no
    # real performance advantage versus running one group after the other, but we will at least be able to see how both
    # groups are performing without waiting for one to finish. Right now we will use this array to build our targets
    # and then return it so that we can use it to maintain information about the corresponding child fuzzer processes
    # that we will spawn, allowing us to track how well they are doing.
    #my @targets = @{utils::interleave($grouped_targets->{perm}, $grouped_targets->{hash})};
    my @targets = (@{$grouped_targets->{perm}}, @{$grouped_targets->{hash}}, @{$grouped_targets->{max2}});
    unshift @targets, $grouped_targets->{max} if $grouped_targets->{max};

    # Build all the targets!
    my $num_targets = scalar @targets;
    my $i = 1;
    foreach my $target (@targets) {
        $log->info("[$i/$num_targets] Building $target->{name}" . ($options->{use_asan} ? "-asan" : ""));
        build(
            $experiment_name,
            $subject,
            $version,
            $target->{waypoints},
            $target->{name} . ($options->{use_asan} ? "-asan" : ""),
            {
                use_existing           => 1,
                backup                 => 0,
                m32                    => $options->{use_asan},
                clang_waypoint_options => {
                    variables_file => $target->{variables_file}
                }
            }
        );
        $i++;
    }

    YAML::XS::DumpFile($name_to_id_file, $name_to_id);
    return $main_target, \@targets;
}

sub can_resume {
    my $experiment_name = $_[0];
    my $subject = $_[1];
    my $version = $_[2];

    my $workspace = utils::get_workspace($experiment_name, $subject, $version);
    my $results_dir = "$workspace/results";
    my $sync_dir = "$results_dir/$SANDPUPPY_SYNC_DIRECTORY";
    if (! -d $sync_dir) {
        return 0;
    }

    my $name_to_id = {};
    my $name_to_id_file = "$results_dir/sandpuppy-target-name-to-id.yml";
    if (-e $name_to_id_file) {
        $name_to_id = YAML::XS::LoadFile($name_to_id_file);
    } else {
        return 0;
    }

    my $i = 0;
    my $not_found = 0;
    my @target_names = keys (%{$name_to_id});
    until ($not_found || $i == scalar @target_names) {
        my $target_id = $name_to_id->{$target_names[$i]};

        my $target_dir = "$sync_dir/$target_id";
        my $target_queue = "$target_dir/queue";
        my $target_hangs = "$target_dir/hangs";
        my $target_crashes = "$target_dir/crashes";

        system "echo 'check if we can find $target_dir and $target_queue and $target_hangs and $target_crashes' >> /tmp/notfound";
        $not_found = (! -d $target_dir) || (! -d $target_queue) || (! -d $target_hangs) || (! -d $target_crashes);
        $i++;
    }

    system "echo 'not found is: $not_found' >> /tmp/notfound";
    # We can resume if everything was found.
    return !$not_found;
}

1;