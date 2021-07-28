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
use display;
use infantheap;
use rarebug;
use maze;
use libpng;
use readelf;
use libtpms;
use smbc;

sub shut_down {
    display::restore_display();
    exit;
}

my $log = Log::Simple::Color->new;

my $BASEPATH = glob "~/Projects/phd";
my $TOOLS = "$BASEPATH/tools";

my $WAYPOINTS_NONE = "none";
my $SANDPUPPY_MAIN_TARGET_NAME = "sandpuppy-main";
my $SANDPUPPY_SYNC_DIRECTORY = "sandpuppy-sync";

my $subjects = {
    vctestbed => {
        binary_name => "vctestbed",
        tasks       => {
            build       => \&vctestbed::build,
            fuzz        => create_fuzz_task(\&vctestbed::get_fuzz_command),
            pod_command => create_pod_command_task(\&vctestbed::get_fuzz_command)
        },
        fuzz_time   => 300
    },
    infantheap => {
        binary_name => "infantheap",
        tasks       => {
            build       => \&infantheap::build,
            fuzz        => create_fuzz_task(\&infantheap::get_fuzz_command),
            pod_command => create_pod_command_task(\&infantheap::get_fuzz_command)
        },
        fuzz_time   => 600
    },
    rarebug    => {
        binary_name => "rarebug",
        tasks       => {
            build   => \&rarebug::build,
            fuzz    => create_fuzz_task(\&rarebug::get_fuzz_command),
            pod_command => create_pod_command_task(\&rarebug::get_fuzz_command)
        },
        fuzz_time   => 600
    },
    maze       => {
        binary_name => "maze",
        source_name => "maze.c",
        tasks       => {
            build   => \&maze::build,
            fuzz    => create_fuzz_task(\&maze::get_fuzz_command),
            pod_command => create_pod_command_task(\&maze::get_fuzz_command)
        },
        fuzz_time   => 360
    },
    maze_ijon  => {
        binary_name => "maze_ijon",
        source_name => "maze_ijon.c",
        tasks       => {
            build   => \&maze::build,
            fuzz    => create_fuzz_task(\&maze::get_fuzz_command),
            pod_command => create_pod_command_task(\&maze::get_fuzz_command)
        },
        fuzz_time   => 360
    },
    maze_klee  => {
        binary_name => "maze_klee",
        source_name => "maze_klee.c",
        tasks       => {
            build   => \&maze::build,
            fuzz    => create_fuzz_task(\&maze::get_fuzz_command),
            pod_command => create_pod_command_task(\&maze::get_fuzz_command)
        },
        fuzz_time   => 360
    },
    libpng     => {
        binary_name => "readpng",
        tasks       => {
            build   => \&libpng::build,
            fuzz    => create_fuzz_task(\&libpng::get_fuzz_command),
            pod_command => create_pod_command_task(\&libpng::get_fuzz_command)
        },
        fuzz_time   => 600
    },
    readelf    => {
        binary_name => "readelf",
        tasks       => {
            build   => \&readelf::build,
            fuzz    => create_fuzz_task(\&readelf::get_fuzz_command),
            pod_command => create_pod_command_task(\&readelf::get_fuzz_command)
        },
        fuzz_time   => 600
    },
    libtpms    => {
        binary_name => "readtpmc",
        tasks       => {
            build   => \&libtpms::build,
            fuzz    => create_fuzz_task(\&libtpms::get_fuzz_command),
            pod_command => create_pod_command_task(\&libtpms::get_fuzz_command)
        },
        fuzz_time   => 600
    },
    smbc       => {
        binary_name => "smbc",
        tasks       => {
            build   => \&smbc::build,
            fuzz    => create_fuzz_task(\&smbc::get_fuzz_command),
            pod_command => create_pod_command_task(\&smbc::get_fuzz_command)
        },
        fuzz_time   => 360
    }
};

sub create_pod_command_task {
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
        print(">>>> $fuzz_command <<<<\n");

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

sub pod_command {
    my $subject = $_[1];

    my $tasks = $subjects->{$subject}->{tasks};
    return $tasks->{pod_command}->(@_);
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

    if ($options->{use_kubernetes}) {
        sandpuppy_fuzz_k8s($experiment_name, $subject, $version, $main_target, $targets, $options);
    } else {
        sandpuppy_fuzz_local($experiment_name, $subject, $version, $main_target, $targets);
    }
}

sub sandpuppy_fuzz_k8s {
    my $experiment_name = $_[0];
    my $subject = $_[1];
    my $version = $_[2];
    my $main_target = $_[3];
    my $targets = $_[4];
    my $options = $_[5];

    my $num_targets = scalar @{$targets} + 1; # Account for main target

    my $full_subject = $subject . ($version ? "-$version" : "");

    my $id_to_pod_name_and_target = {};
    my $pod_name_to_create_command = {};

    $log->info("Fuzzing using kubernetes requested.\n");

    # TODO: do distributed parallel.

    #$log->info("Copying target binaries to NFS mount");

    my $workspace = utils::get_workspace($experiment_name, $subject, $version);
    my $subject_directory = utils::get_subject_directory($experiment_name, $subject, $version);
    my $local_nfs_workspace = "/mnt/vivin-nfs/vivin/$subject_directory";
    my $container_nfs_workspace = "/private-nfs/vivin/$subject_directory";

    if (! -d $local_nfs_workspace) {
        system("mkdir -p $local_nfs_workspace");
    }

    if (! -d "$local_nfs_workspace/results") {
        system("mkdir $local_nfs_workspace/results");
    }

    if (! -d "$local_nfs_workspace/binaries") {
        system("mkdir $local_nfs_workspace/binaries");
    }

    my $main_target_binary_dir = $main_target->{binary_context};
    if (! -e -d "$local_nfs_workspace/binaries/$main_target_binary_dir") {
        system("mkdir $local_nfs_workspace/binaries/$main_target_binary_dir");
    }

    my @main_target_files = `find "$workspace/binaries/$main_target_binary_dir" -type f | sed -e 's,^.*/,,'`;
    foreach my $main_target_file (@main_target_files) {
        chomp($main_target_file);

        my $local_file_path = "$workspace/binaries/$main_target_binary_dir/$main_target_file";
        my $nfs_file_path = "$local_nfs_workspace/binaries/$main_target_binary_dir/$main_target_file";

        if (-e -f $nfs_file_path) {
            my $ctime_local_file = stat($local_file_path)->ctime;
            my $ctime_nfs_file = stat($nfs_file_path)->ctime;

            if ($ctime_nfs_file >= $ctime_local_file) {
                $log->info("[1/$num_targets] Not copying $main_target_binary_dir/$main_target_file because it already exists on NFS and is newer.");
            } else {
                $log->info("[1/$num_targets] Copying $main_target_binary_dir/$main_target_file to NFS as it is newer than the existing one..");
                system("cp $local_file_path $nfs_file_path")
            }
        } else {
            $log->info("[1/$num_targets] Copying $main_target_binary_dir/$main_target_file to NFS.");
            system("cp $local_file_path $nfs_file_path")
        }
    }

    my $pod_name = "$experiment_name-$full_subject--$main_target->{id}" . ($options->{use_asan} ? "-asan" : "");
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
        pod_command(
            $experiment_name,
            $subject,
            $version,
            $main_target->{waypoints},
            $main_target->{binary_context},
            $main_target->{execution_context},
            {
                async              => 1,
                fuzzer_id          => $main_target->{id},
                #sync_directory_name => $SANDPUPPY_SYNC_DIRECTORY,
                parallel_fuzz_mode => "parent",
                resume             => $options->{resume}
            }
        )
    );

    #if (! -f "$local_nfs_workspace/$main_target->{id}") {
        open my $TARGET_SCRIPT, ">", "$local_nfs_workspace/$main_target->{id}";
        print $TARGET_SCRIPT $target_script;
        close $TARGET_SCRIPT;
    #}

    system "chmod 755 $local_nfs_workspace/$main_target->{id}";

    print "\n";

    my $pod_command = "$container_nfs_workspace/$main_target->{id}";
    $pod_name_to_create_command->{$pod_name} = {
        target   => $main_target->{id},
        command  => "kuboid/scripts/pod_create -n \"$pod_name\" -s /tmp/sandpuppy.existing -i vivin/sandpuppy $pod_command",
        sort_key => "a" # so that it always shows up first
    };

    my $i = 2; # Account for main target
    foreach my $target (@{$targets}) {
        my $target_binary_dir = $target->{binary_context};
        if (! -e -d "$local_nfs_workspace/binaries/$target_binary_dir") {
            system("mkdir $local_nfs_workspace/binaries/$target_binary_dir");
        }

        my @target_files = `find "$workspace/binaries/$target_binary_dir" -type f | sed -e 's,^.*/,,'`;
        foreach my $target_file (@target_files) {
            chomp($target_file);

            my $local_file_path = "$workspace/binaries/$target_binary_dir/$target_file";
            my $nfs_file_path = "$local_nfs_workspace/binaries/$target_binary_dir/$target_file";

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
            "$experiment_name-$full_subject--$target->{id}$asan_suffix" :
            "$experiment_name-$full_subject--$target->{id}-$target->{waypoints}$asan_suffix";
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
            pod_command(
                $experiment_name,
                $subject,
                $version,
                $target->{waypoints},
                $target->{binary_context},
                $target->{execution_context},
                {
                    async              => 1,
                    fuzzer_id          => $target->{id},
                    #sync_directory_name => $SANDPUPPY_SYNC_DIRECTORY,
                    parallel_fuzz_mode => "child",
                    resume             => $options->{resume}
                    #exit_when_done      => 1
                }
            )
        );

        #if (! -f "$local_nfs_workspace/$target->{id}") {
            open $TARGET_SCRIPT, ">", "$local_nfs_workspace/$target->{id}";
            print $TARGET_SCRIPT $target_script;
            close $TARGET_SCRIPT;

            system "chmod 755 $local_nfs_workspace/$target->{id}";
        #}

        $pod_command = "$container_nfs_workspace/$target->{id}";
        $pod_name_to_create_command->{$pod_name} = {
            target   => $target->{id},
            command  => "kuboid/scripts/pod_create -n \"$pod_name\" -s /tmp/sandpuppy.existing -i vivin/sandpuppy $pod_command",
            sort_key => $target->{name}
        };

        print "\n";
        $i++;
    }

    $log->info("Preparing to create and run kubernetes pods for targets...");

    my $id_to_pod_name_and_target_file = "$local_nfs_workspace/results/id_to_pod_name_and_target.yml";
    YAML::XS::DumpFile($id_to_pod_name_and_target_file, $id_to_pod_name_and_target);

    if (1) {
        exit(0);
    }

    $log->info("Getting list of existing pods (so that we don't recreate)...");
    system ("kuboid/scripts/pod_names > /tmp/sandpuppy.existing");

    $i = 1;
    foreach $pod_name (sort { $pod_name_to_create_command->{$a}->{sort_key} cmp $pod_name_to_create_command->{$b}->{sort_key} } keys %{$pod_name_to_create_command}) {
        my $target = $pod_name_to_create_command->{$pod_name}->{target};
        my $command = $pod_name_to_create_command->{$pod_name}->{command};

        $log->info("[$i/$num_targets] Creating pod $pod_name for target $target");
        system ($command);
        if ($? != 0) {
            print "[$i/$num_targets] Creating pod failed: $!\n";
        }

        print "\n";

        $i++;
    }

    my $requested_pods = scalar @{$targets} + 1;
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

sub sandpuppy_fuzz_local {
    my $experiment_name = $_[0];
    my $subject = $_[1];
    my $version = $_[2];
    my $main_target = $_[3];
    my $targets = $_[4];

    my $NUM_CORES = 12;
    my $OVERALL_FUZZ_TIME = 302400; # For 3.5 days

    # We reserve one core to run the parent fuzzer which we won't shut down until we are completely done.
    my $AVAILABLE_CORES = $NUM_CORES - 1;

    my $resume = can_resume($experiment_name, $subject, $version);

    # Now we will start parallel fuzzing. First we clear the screen, set up some signal handlers (that restore the
    # terminal to a non-annoying state on shutdown) and then start the parent fuzzer instance.
    display::init_display();
    $SIG{INT} = \&shut_down;
    $SIG{TERM} = \&shut_down;

    my $overall_start_time = time();
    my $parent_fuzzer_pid = fuzz(
        $experiment_name,
        $subject,
        $version,
        $main_target->{waypoints},
        $main_target->{binary_context},
        $main_target->{execution_context},
        {
            async               => 1,
            fuzzer_id           => $main_target->{id},
            sync_directory_name => $SANDPUPPY_SYNC_DIRECTORY,
            parallel_fuzz_mode  => "parent",
            resume              => $resume
        }
    );

    my $cycle = 1;
    my $done = 0;
    while (!$done) {
        # Only include unfinished targets.
        my @unfinished_targets = grep { !$_->{finished} } @{$targets};

        # Retrieve stats from results directory for each target. This gives us more accurate numbers for metrics like
        # paths found, paths imported, etc. than relying solely on plot_data. This is because in a resumed fuzzing
        # session, the data reported by afl-fuzz only includes data from the current session. So the number of paths
        # found, for example, will not include those discovered in previous sessions. Since we support resuming a
        # previous sandpuppy fuzzing session, and because we also resume fuzzing targets after the first cycle, we need
        # this data so that we can display accurate metrics.
        $main_target->{previous_stats} = get_previous_parallel_fuzzer_stats($main_target);
        foreach my $target (@unfinished_targets) {
            $target->{previous_stats} = get_previous_parallel_fuzzer_stats($target);
        }

        # If we have more targets than available cores, we cannot fuzz all of them at once. So we chunk the list into
        # sub-lists that are at most AVAILABLE_CORES in size.
        my @target_batches = @{utils::chunk(\@unfinished_targets, $AVAILABLE_CORES)};
        my $num_batches = scalar @target_batches;

        # Iterate over each chunk. Spin up child fuzzers. Wait for an hour, then kill them and gather their stats. Once
        # done with all chunks, sort targets by number of paths found in descending order. Then re-chunk and fuzz again.
        # Fuzz each batch for an hour. Unless there is only one batch, in which case we just fuzz that one batch for the
        # whole $OVERALL_FUZZ_TIME seconds.
        my $BATCH_FUZZ_TIME = $num_batches == 1 ? $OVERALL_FUZZ_TIME : 3600; # Fuzz each batch for one hour.
        my $current_batch = 1;
        foreach my $target_batch (@target_batches) {

            # Spin up fuzzers for all targets in this batch.
            foreach my $target (@{$target_batch}) {
                my $fuzzer_pid = fuzz(
                    $experiment_name,
                    $subject,
                    $version,
                    $target->{waypoints},
                    $target->{binary_context},
                    $target->{execution_context},
                    {
                        async               => 1,
                        fuzzer_id           => $target->{id},
                        sync_directory_name => $SANDPUPPY_SYNC_DIRECTORY,
                        parallel_fuzz_mode  => "child",
                        resume              => $resume || $cycle > 1 ? 1 : 0,
                        exit_when_done      => 1
                    }
                );

                $target->{fuzzer_pid} = $fuzzer_pid;
            }

            my $batch_start_time = time();
            my $batch_done = 0;
            while (!$batch_done) {
                $main_target->{current_stats} = get_current_parallel_fuzzer_stats($main_target, $batch_start_time);
                foreach my $target (@{$target_batch}) {
                    $target->{current_stats} = get_current_parallel_fuzzer_stats($target, $batch_start_time);
                }

                my @all_targets = ($main_target, @{$targets});
                my $batch_stats = aggregate_stats($target_batch);
                my $overall_stats = aggregate_stats(\@all_targets);

                display::display_stats(
                    $subject . ($version ? "-$version" : ""),
                    $overall_start_time,
                    $batch_start_time,
                    $cycle,
                    $current_batch,
                    $num_batches,
                    $overall_stats,
                    $batch_stats
                );

                check_for_finished_targets($target_batch);
                sleep 1;

                $batch_done = time() - $batch_start_time > $BATCH_FUZZ_TIME
                    || scalar (grep { !$_->{finished} } @{$target_batch}) == 0;
            }

            # Kill any children that are not already finished.
            kill 'INT', map { $_->{fuzzer_pid} } grep { !$_->{finished} } @{$target_batch};

            # Get latest stats after killing children because fuzzers may have updated plot_data right before we killed
            # them. While we are here we are also going to do our own checks to see whether a target is done fuzzing.
            # This is because AFL waits until a target has gone through 100 cycles without finding any new paths and
            # without any pending paths to fuzz, before deciding to exit. Our problem is that for slow targets it is
            # unlikely that afl-fuzz will get through 100 cycles in a single session. But we can still tell how many
            # cycles it did go through. So what we do is maintain a cumulative count of cycles that the target completed
            # without finding any paths, and if this gets above 100 we check to see if there are any pending paths. If
            # not, increment a counter that maintains the number of unproductive fuzzing sessions. If this counter gets
            # above 1 (meaning that we fuzzed for at least 2 hours without any new paths) we mark the corresponding
            # target as finished.
            $main_target->{current_stats} = get_current_parallel_fuzzer_stats($main_target, $batch_start_time);
            foreach my $target (@{$target_batch}) {
                $target->{current_stats} = get_current_parallel_fuzzer_stats($target, $batch_start_time);

                # If target was already shut down by AFL there's no need for us to figure out if it is done.
                next if $target->{finished};

                if (!$target->{cycles_without_finds}) {
                    $target->{cycles_without_finds} = 0;
                }

                if (!$target->{unproductive_fuzzing_sessions}) {
                    $target->{unproductive_fuzzing_sessions} = 0;
                }

                # If no paths were found, update the number of cycles without finds. If any paths were found reset it to
                # zero.
                if ($target->{current_stats}->{paths_found} == 0) {
                    $target->{cycles_without_finds} += $target->{current_stats}->{cycles_done};

                    my $cycles_without_finds = $target->{cycles_without_finds};
                    if ($cycles_without_finds > 100 && $target->{current_stats}->{pending_total} == 0) {
                        $target->{unproductive_fuzzing_sessions}++;
                    }
                } elsif ($target->{current_stats}->{paths_found} > 0) {
                    $target->{cycles_without_finds} = 0;
                }

                if ($target->{unproductive_fuzzing_sessions} > 1) {
                    $target->{finished} = 1;
                }
            }

            $current_batch++;
        }

        # Sort all targets in descending order based on number of found paths
        my @sorted = sort { $b->{current_stats}->{paths_found} <=> $a->{current_stats}->{paths_found} } @{$targets};
        $targets = \@sorted;

        $cycle++;

        # We are done if the fuzzing time limit is over, or if there are no unfinished targets left.
        $done = time() - $overall_start_time > $OVERALL_FUZZ_TIME
            || scalar (grep { !$_->{finished} } @{$targets}) == 0;
    }

    display::restore_display();
    kill 'INT', $parent_fuzzer_pid;
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
            foreach my $shift_width (4, 8) {
                # If the value is within the 8 bit signed or unsigned range, there is really no point doing a value
                # permutation pass with a shift width of 8.
                next if $shift_width == 8 &&
                    (($min_value >= 0 && $max_value <= 255) || ($min_value >= -128 && $max_value <= 127));

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

sub get_previous_parallel_fuzzer_stats {
    my $target = $_[0];

    my $workspace = utils::get_workspace($target->{experiment_name}, $target->{subject}, $target->{version});
    my $results_base = "$workspace/results";
    my $results_dir = "$results_base/$SANDPUPPY_SYNC_DIRECTORY/$target->{id}";

    if (! -d $results_dir || ! -d "$results_dir/queue" || ! -d "$results_dir/hangs" || ! -d "$results_dir/crashes") {
        return {
            paths_total    => 0,
            paths_found    => 0,
            paths_imported => 0,
            unique_hangs   => 0,
            unique_crashes => 0
        };
    }

    chomp(my $num_queue_inputs = `find $results_dir/queue -maxdepth 1 -type f | wc -l`);
    chomp(my $num_original_inputs =`find $results_dir/queue -maxdepth 1 -type f | grep ",orig:" | wc -l`);
    chomp(my $num_imported_inputs =`find $results_dir/queue -maxdepth 1 -type f | grep ",sync:" | wc -l`);

    chomp(my $num_hanging_inputs = `find $results_dir -maxdepth 2 -type f -name "id:*" | grep "/hangs" | sed -e 's,^.*/id,id,' | sort | uniq | wc -l`);
    chomp(my $num_hanging_imported_inputs = `find $results_dir -maxdepth 2 -type f -name "id:*" | grep "/hangs" | sed -e 's,^.*/id,id,' | grep ",sync:" | sort | uniq | wc -l`);

    chomp(my $num_crashing_inputs = `find $results_dir -maxdepth 2 -type f -name "id:*" | grep "/crashes" | sed -e 's,^.*/id,id,' | sort | uniq | wc -l`);
    chomp(my $num_crashing_imported_inputs = `find $results_dir -maxdepth 2 -type f -name "id:*" | grep "/crashes" | sed -e 's,^.*/id,id,' | grep ",sync:" | sort | uniq | wc -l`);

    my $paths_imported = $num_imported_inputs + $num_hanging_imported_inputs + $num_crashing_imported_inputs;
    my $total_paths = $num_queue_inputs + $paths_imported + $num_hanging_inputs + $num_crashing_inputs;
    my $paths_found = $total_paths - $num_original_inputs - $num_imported_inputs - $num_hanging_imported_inputs - $num_crashing_imported_inputs;

    my $unique_hangs = $num_hanging_inputs;
    my $unique_crashes = $num_crashing_inputs;

    my %stats = (
        paths_total    => $total_paths,
        paths_found    => $paths_found,
        paths_imported => $paths_imported,
        unique_hangs   => $unique_hangs,
        unique_crashes => $unique_crashes
    );

    return \%stats;
}

sub get_current_parallel_fuzzer_stats {
    my $target = $_[0];
    my $batch_start_time = $_[1];

    my @stats_columns = (
        "unix_time", "cycles_done", "cur_path", "paths_total", "paths_found", "paths_imported", "pending_total",
        "pending_favs", "map_coverage", "unique_crashes", "unique_hangs", "max_depth", "execs_per_sec"
    );
    my %stats = (
        paths_total         => 0,
        paths_found         => 0,
        paths_imported      => 0,
        pending_total       => $target->{current_stats} ? $target->{current_stats}->{pending_total} : 0,
        unique_hangs        => 0,
        unique_crashes      => 0,
        max_depth           => $target->{current_stats} ? $target->{current_stats}->{max_depth} : 0,
        cycles_done         => $target->{current_stats} ? $target->{current_stats}->{cycles_done} : 0,
        cur_path            => 0,
        last_new_path_found => -1
    );
    if ($target->{current_stats} && defined $target->{current_stats}->{last_new_path_found}) {
        $stats{last_new_path_found} = $target->{current_stats}->{last_new_path_found};
    }

    my $workspace = utils::get_workspace($target->{experiment_name}, $target->{subject}, $target->{version});
    my $results_base = "$workspace/results";
    my $results_dir = "$results_base/$SANDPUPPY_SYNC_DIRECTORY/$target->{id}";
    my $plot_data_file = "$results_dir/plot_data";

    # We will use plot_data instead of fuzzer_stats because plot_data is updated more frequently. But sometimes the
    # fuzzer may not be ready yet and so plot_data may not exist or may be empty. We also want to make sure that
    # the last modified time of the file is after we started this particular batch, because otherwise we end up getting
    # data from the previous session.
    if ((! -e $plot_data_file) || (-z $plot_data_file) || stat($plot_data_file)->mtime < $batch_start_time) {
        return \%stats;
    }

    # If there are at least two lines in the file, then we have data. This is because the first line is for the header.
    chomp(my $num_lines = `wc -l $plot_data_file | awk '{ print \$1 }'`);
    if ($num_lines > 1) {
        chomp(my $line = `tail -1 $plot_data_file`);
        my @components = split /,\s+/, $line;

        %stats = map {($stats_columns[$_] => $components[$_])} (0 .. (scalar @stats_columns - 1));
        $stats{last_new_path_found} = $target->{current_stats} ? $target->{current_stats}->{last_new_path_found} : -1;

        if ((!$target->{current_stats} && $stats{paths_found} > 0) ||
            ($target->{current_stats} && $stats{paths_found} > $target->{current_stats}->{paths_found})) {
            $stats{last_new_path_found} = time();
        }
    }

    return \%stats;
}

sub aggregate_stats {
    my $targets = $_[0];

    my %stats = (
        waypoints => {},
        aggregate => {}
    );

    my $count = scalar @{$targets};
    my $finished = 0;
    my $total_paths = 0;
    my $paths_imported = 0;
    my $paths_found = 0;
    my $paths_found_in_batch = 0;
    my $unique_hangs = 0;
    my $unique_hangs_in_batch = 0;
    my $unique_crashes = 0;
    my $unique_crashes_in_batch = 0;
    my $max_depth = 0;
    my $path_progress = [];
    my $cycles_done = [];
    my $execs_per_sec = [];
    my $last_new_path_found = -1;

    foreach my $target (sort { $a->{name} cmp $b->{name} } @{$targets}) {

        if (!$stats{waypoints}->{$target->{waypoints}}) {
            $stats{waypoints}->{$target->{waypoints}} = {
                count                   => 0,
                finished                => 0,
                total_paths             => 0,
                paths_imported          => 0,
                paths_found             => 0,
                paths_found_in_batch    => 0,
                unique_hangs            => 0,
                unique_hangs_in_batch   => 0,
                unique_crashes          => 0,
                unique_crashes_in_batch => 0,
                max_depth               => 0,
                last_new_path_found     => -1
            }
        }

        $stats{waypoints}->{$target->{waypoints}}->{count}++;
        next if !$target->{current_stats};

        my $previous_paths_total = $target->{previous_stats}->{paths_total};
        my $previous_paths_imported = $target->{previous_stats}->{paths_imported};
        my $previous_paths_found = $target->{previous_stats}->{paths_found};
        my $previous_unique_hangs = $target->{previous_stats}->{unique_hangs};
        my $previous_unique_crashes = $target->{previous_stats}->{unique_crashes};

        my $current_paths_imported = $target->{current_stats}->{paths_imported};
        my $current_paths_found = $target->{current_stats}->{paths_found};
        my $current_unique_hangs = $target->{current_stats}->{unique_hangs};
        my $current_unique_crashes = $target->{current_stats}->{unique_crashes};
        my $current_max_depth = $target->{current_stats}->{max_depth};
        my $current_cur_path = $target->{current_stats}->{cur_path};
        my $current_cycles_done = $target->{current_stats}->{cycles_done};
        my $current_execs_per_sec = $target->{current_stats}->{execs_per_sec};
        my $current_last_new_path_found = $target->{current_stats}->{last_new_path_found};

        my $target_total_paths = $previous_paths_total + $current_paths_found + $current_paths_imported;
        my $target_paths_imported = $previous_paths_imported + $current_paths_imported;
        my $target_paths_found = $previous_paths_found + $current_paths_found;
        my $target_unique_hangs = $previous_unique_hangs + $current_unique_hangs;
        my $target_unique_crashes = $previous_unique_crashes + $current_unique_crashes;

        if ($target->{finished}) {
            $stats{waypoints}->{$target->{waypoints}}->{finished}++;
            $finished++;
        }

        $total_paths += $target_total_paths;
        $paths_imported += $target_paths_imported;
        $paths_found += $target_paths_found;
        $paths_found_in_batch += $current_paths_found;
        $unique_hangs += $target_unique_hangs;
        $unique_hangs_in_batch += $current_unique_hangs;
        $unique_crashes += $target_unique_crashes;
        $unique_crashes_in_batch += $current_unique_crashes;
        $max_depth = $max_depth < $current_max_depth ? $current_max_depth : $max_depth;
        push @{$path_progress},
            { waypoints => $target->{waypoints}, path_progress => $target_total_paths == 0 ? 0 : ($current_cur_path / $target_total_paths) * 100 };
        push @{$cycles_done},
            { waypoints => $target->{waypoints}, cycles_done => $current_cycles_done };
        push @{$execs_per_sec},
            { waypoints => $target->{waypoints}, execs_per_sec => $current_execs_per_sec ? $current_execs_per_sec : 0 };

        if ($current_last_new_path_found > $last_new_path_found) {
            $last_new_path_found = $current_last_new_path_found;
        }

        $stats{waypoints}->{$target->{waypoints}}->{total_paths} += $target_total_paths;
        $stats{waypoints}->{$target->{waypoints}}->{paths_imported} += $target_paths_imported;
        $stats{waypoints}->{$target->{waypoints}}->{paths_found} += $target_paths_found;
        $stats{waypoints}->{$target->{waypoints}}->{paths_found_in_batch} += $current_paths_found;
        $stats{waypoints}->{$target->{waypoints}}->{unique_hangs} += $target_unique_hangs;
        $stats{waypoints}->{$target->{waypoints}}->{unique_hangs_in_batch} += $current_unique_hangs;
        $stats{waypoints}->{$target->{waypoints}}->{unique_crashes} += $target_unique_crashes;
        $stats{waypoints}->{$target->{waypoints}}->{unique_crashes_in_batch} += $current_unique_crashes;

#        print Dumper($target);
#        print Dumper(\%stats);
        if ($current_max_depth > $stats{waypoints}->{$target->{waypoints}}->{max_depth}) {
            $stats{waypoints}->{$target->{waypoints}}->{max_depth} = $current_max_depth;
        }

        if ($current_last_new_path_found > $stats{waypoints}->{$target->{waypoints}}->{last_new_path_found}) {
            $stats{waypoints}->{$target->{waypoints}}->{last_new_path_found} = $current_last_new_path_found;
        }
    }

    $stats{aggregate}->{count} = $count;
    $stats{aggregate}->{finished} = $finished;
    $stats{aggregate}->{total_paths} = $total_paths;
    $stats{aggregate}->{paths_imported} = $paths_imported;
    $stats{aggregate}->{paths_found} = $paths_found;
    $stats{aggregate}->{unique_hangs} = $unique_hangs;
    $stats{aggregate}->{unique_crashes} = $unique_crashes;
    $stats{aggregate}->{max_depth} = $max_depth;
    $stats{aggregate}->{path_progress} = $path_progress;
    $stats{aggregate}->{cycles_done} = $cycles_done;
    $stats{aggregate}->{execs_per_sec} = $execs_per_sec;
    $stats{aggregate}->{last_new_path_found} = $last_new_path_found;

    return \%stats;
}

sub check_for_finished_targets {
    my $targets = $_[0];
    foreach my $target (@{$targets}) {
        $target->{finished} = !kill 'ZERO', $target->{fuzzer_pid};
    }
}

1;