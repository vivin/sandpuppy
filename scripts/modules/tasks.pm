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
use lavam;
use pcapplusplus;
use jsoncpp;

my $log = Log::Simple::Color->new;

my $BASE_PATH = glob "~/Projects/phd";
my $TOOLS = "$BASE_PATH/tools";
my $RESOURCES = "$BASE_PATH/resources";

my $WAYPOINTS_NONE = "none";
my $SANDPUPPY_MAIN_TARGET_NAME = "sandpuppy-main";
my $SANDPUPPY_SYNC_DIRECTORY = "sandpuppy-sync";

my $fuzz_config = YAML::XS::LoadFile("$BASE_PATH/resources/fuzz_config.yml");

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
        fuzz_time   => $fuzz_config->{libpng}->{fuzz_time}
    },
    readelf     => {
        binary_name => "readelf",
        tasks       => {
            build            => \&readelf::build,
            fuzz             => create_fuzz_task(\&readelf::get_fuzz_command),
            pod_fuzz_command => create_pod_fuzz_command_task(\&readelf::get_fuzz_command)
        },
        fuzz_time   => $fuzz_config->{readelf}->{fuzz_time}
    },
    libtpms     => {
        binary_name => "readtpmc",
        tasks       => {
            build            => \&libtpms::build,
            fuzz             => create_fuzz_task(\&libtpms::get_fuzz_command),
            pod_fuzz_command => create_pod_fuzz_command_task(\&libtpms::get_fuzz_command)
        },
        fuzz_time   => $fuzz_config->{libtpms}->{fuzz_time}
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
        fuzz_time   => $fuzz_config->{dmg2img}->{fuzz_time}
    },
    libtins     => {
        binary_name => "readpcap",
        tasks       => {
            build            => \&libtins::build,
            fuzz             => create_fuzz_task(\&libtins::get_fuzz_command),
            pod_fuzz_command => create_pod_fuzz_command_task(\&libtins::get_fuzz_command)
        },
        fuzz_time   => 360
    },
    base64      => {
        binary_name => "base64",
        tasks       => {
            build            => \&lavam::build,
            fuzz             => create_fuzz_task(\&lavam::get_fuzz_command),
            pod_fuzz_command => create_pod_fuzz_command_task(\&lavam::get_fuzz_command)
        },
        fuzz_time   => 360
    },
    md5sum      => {
        binary_name => "md5sum",
        tasks       => {
            build            => \&lavam::build,
            fuzz             => create_fuzz_task(\&lavam::get_fuzz_command),
            pod_fuzz_command => create_pod_fuzz_command_task(\&lavam::get_fuzz_command)
        },
        fuzz_time   => 360
    },
    who         => {
        binary_name => "who",
        tasks       => {
            build            => \&lavam::build,
            fuzz             => create_fuzz_task(\&lavam::get_fuzz_command),
            pod_fuzz_command => create_pod_fuzz_command_task(\&lavam::get_fuzz_command)
        },
        fuzz_time   => 360
    },
    uniq        => {
        binary_name => "uniq",
        tasks       => {
            build            => \&lavam::build,
            fuzz             => create_fuzz_task(\&lavam::get_fuzz_command),
            pod_fuzz_command => create_pod_fuzz_command_task(\&lavam::get_fuzz_command)
        },
        fuzz_time   => 360
    },
    pcapplusplus     => {
        binary_name => "readpcap",
        tasks       => {
            build            => \&pcapplusplus::build,
            fuzz             => create_fuzz_task(\&pcapplusplus::get_fuzz_command),
            pod_fuzz_command => create_pod_fuzz_command_task(\&pcapplusplus::get_fuzz_command)
        },
        fuzz_time   => $fuzz_config->{pcapplusplus}->{fuzz_time}
    },
    jsoncpp     => {
        binary_name => "readjson",
        tasks       => {
            build            => \&jsoncpp::build,
            fuzz             => create_fuzz_task(\&jsoncpp::get_fuzz_command),
            pod_fuzz_command => create_pod_fuzz_command_task(\&jsoncpp::get_fuzz_command)
        },
        fuzz_time   => $fuzz_config->{jsoncpp}->{fuzz_time}
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

sub initialize_subject_directory {
    my $experiment_name = $_[0];
    my $subject = $_[1];
    my $version = $_[2];

    if (!$subjects->{$subject}) {
        die "No subject named $subject";
    }

    my $subject_directory = utils::get_subject_directory($experiment_name, $subject, $version);
    if (!-d $subject_directory) {
        $log->info("Creating $subject_directory");
        make_path($subject_directory);
    }

    if (!-d "$subject_directory/binaries") {
        $log->info("Creating $subject_directory/binaries");
        make_path("$subject_directory/binaries");
    }

    if (!-d "$subject_directory/results") {
        $log->info("Creating $subject_directory/results");
        make_path("$subject_directory/results");
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

    my $subject_directory = utils::get_subject_directory($experiment_name, $subject, $version);
    my $binary = "$subject_directory/binaries/$binary_context/$subjects->{$subject}->{binary_name}";

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

        chdir $BASE_PATH;
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

sub vvdump_fuzz {
    my $experiment_name = $_[0];
    my $subject = $_[1];
    my $version = $_[2];
    my $waypoints = $_[3];
    my $binary_context = $_[4];
    my $execution_context = $_[5];
    my $options = $_[6];

    utils::setup_named_pipe();

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

sub initialize_nfs_subject_directory {
    my $experiment_name = $_[0];
    my $subject = $_[1];
    my $version = $_[2];
    my $run_name = $_[3];

    if (!$subjects->{$subject}) {
        die "No subject named $subject";
    }

    my $nfs_subject_directory = utils::get_nfs_subject_directory($experiment_name, $subject, $version);
    if (!-d $nfs_subject_directory) {
        $log->info("Creating $nfs_subject_directory");
        make_path($nfs_subject_directory);
    }

    if (!-d "$nfs_subject_directory/binaries") {
        $log->info("Creating $nfs_subject_directory/binaries");
        make_path("$nfs_subject_directory/binaries");
    }

    if (!-d "$nfs_subject_directory/results/$run_name") {
        $log->info("Creating $nfs_subject_directory/results");
        make_path("$nfs_subject_directory/results/$run_name");
    }
}

sub setup_fuzz_eval {
    my $experiment_name = $_[0];
    my $subject = $_[1];
    my $version = $_[2];
    my $options = $_[3];

    my $full_subject = $subject . ($version ? "-$version" : "");

    my $run_name = $options->{run_name};
    initialize_nfs_subject_directory($experiment_name, $subject, $version, $run_name);

    my $nfs_subject_directory = utils::get_nfs_subject_directory($experiment_name, $subject, $version);

    $log->info("Copying seeds to fuzz directory...");
    my $nfs_seeds_dir = utils::get_nfs_subject_directory($experiment_name, $subject, $version) . "/seeds/$run_name";
    if (! -e $nfs_seeds_dir) {
        make_path $nfs_seeds_dir;
    }

    system("cp -a $RESOURCES/seeds/$subject/fuzz/. $nfs_seeds_dir/");

    if (-d "$RESOURCES/seeds/$subject/dictionary") {
        $log->info("Copying dictionary...");
        my $nfs_dictionary_dir = utils::get_nfs_subject_directory($experiment_name, $subject, $version) . "/dictionary/$run_name";
        make_path $nfs_dictionary_dir;

        system("cp -a $RESOURCES/seeds/$subject/dictionary/. $nfs_dictionary_dir/");
    }

    foreach my $fuzzer("afl-plain", "aflplusplus-plain", "aflplusplus-lafintel", "aflplusplus-redqueen") {
        $log->info("Copying files for $fuzzer evaluation...");
        copy_target_files_to_nfs($experiment_name, $subject, $version, { binary_context => $fuzzer });
        print "\n";

        my $pod_name = "$experiment_name-$full_subject-\$RUN_NAME--\$TARGET_ID";
        my $parent_startup_script = utils::generate_fuzz_eval_startup_script(
            $experiment_name,
            $subject,
            $version,
            $pod_name,
            $fuzzer,
            pod_fuzz_command(
                $experiment_name,
                $subject,
                $version,
                $WAYPOINTS_NONE,
                $fuzzer,
                "\$TARGET_ID",
                {
                    async              => 1,
                    fuzzer_id          => "\$TARGET_ID",
                    parallel_fuzz_mode => "parent",
                    run_name           => $run_name,
                    resume             => 0
                    #exit_when_done      => 1
                }
            ),
            pod_fuzz_command(
                $experiment_name,
                $subject,
                $version,
                $WAYPOINTS_NONE,
                $fuzzer,
                "\$TARGET_ID",
                {
                    async              => 1,
                    fuzzer_id          => "\$TARGET_ID",
                    parallel_fuzz_mode => "parent",
                    run_name           => $run_name,
                    resume             => 1
                    #exit_when_done      => 1
                }
            )
        );
        my $child_startup_script = utils::generate_fuzz_eval_startup_script(
            $experiment_name,
            $subject,
            $version,
            $pod_name,
            $fuzzer,
            pod_fuzz_command(
                $experiment_name,
                $subject,
                $version,
                $WAYPOINTS_NONE,
                $fuzzer,
                "\$TARGET_ID",
                {
                    async              => 1,
                    fuzzer_id          => "\$TARGET_ID",
                    parallel_fuzz_mode => "child",
                    run_name           => $run_name,
                    resume             => 0
                    #exit_when_done      => 1
                }
            ),
            pod_fuzz_command(
                $experiment_name,
                $subject,
                $version,
                $WAYPOINTS_NONE,
                $fuzzer,
                "\$TARGET_ID",
                {
                    async              => 1,
                    fuzzer_id          => "\$TARGET_ID",
                    parallel_fuzz_mode => "child",
                    run_name           => $run_name,
                    resume             => 1
                    #exit_when_done      => 1
                }
            )
        );

        $log->info("Writing out parent startup script for $fuzzer...");

        my $parent_startup_script_name = "$fuzzer.$run_name.parent";
        open my $PARENT_STARTUP_SCRIPT, ">", "$nfs_subject_directory/$parent_startup_script_name";
        print $PARENT_STARTUP_SCRIPT $parent_startup_script;
        close $PARENT_STARTUP_SCRIPT;

        system "chmod 755 $nfs_subject_directory/$parent_startup_script_name";

        $log->info("Writing out child startup script for $fuzzer...");

        my $child_startup_script_name = "$fuzzer.$run_name.child";
        open my $CHILD_STARTUP_SCRIPT, ">", "$nfs_subject_directory/$child_startup_script_name";
        print $CHILD_STARTUP_SCRIPT $child_startup_script;
        close $CHILD_STARTUP_SCRIPT;

        system "chmod 755 $nfs_subject_directory/$child_startup_script_name";
    }
}

sub sandpuppy_fuzz {
    my $experiment_name = $_[0];
    my $subject = $_[1];
    my $version = $_[2];
    my $options = $_[3];

    my $run_name = $options->{run_name};
    my $id_to_pod_name_and_target = {};
    my $pod_information = {};

    # Generate variables files and build targets using the output from the analysis phase (which should be stored
    # under the results for the provided execution_context). The analysis phase identifies interesting variables to
    # instrument, so we will build targets that do just that.
    my ($main_target, $targets) = build_sandpuppy_targets(
        $experiment_name,
        $subject,
        $version,
        $options
    );

    #if (1) { exit(0); }

    # Add main target to targets array. We don't need to treat it differently.
    unshift @{$targets}, $main_target;
    my $num_targets = scalar @{$targets};

    $log->info("Fuzzing using kubernetes requested.\n");

    initialize_nfs_subject_directory($experiment_name, $subject, $version, $run_name);

    $log->info("Copying seeds to fuzz directory...");
    my $nfs_seeds_dir = utils::get_nfs_subject_directory($experiment_name, $subject, $version) . "/seeds/$run_name";
    if (! -e $nfs_seeds_dir) {
        make_path $nfs_seeds_dir;
    }

    system("cp -a $RESOURCES/seeds/$subject/fuzz/. $nfs_seeds_dir/");

    if (-d "$RESOURCES/seeds/$subject/dictionary") {
        $log->info("Copying dictionary...");
        my $nfs_dictionary_dir = utils::get_nfs_subject_directory($experiment_name, $subject, $version) . "/dictionary/$run_name";
        make_path $nfs_dictionary_dir;

        system("cp -a $RESOURCES/seeds/$subject/dictionary/. $nfs_dictionary_dir/");
    }

    my $i = 1;
    foreach my $target (@{$targets}) {
        $log->info("[$i/$num_targets] Copying $target->{binary_context} ($target->{id}) files...");
        copy_target_files_to_nfs($experiment_name, $subject, $version, $target);
        print "\n";

        $log->info("[$i/$num_targets] Generating pod information for $target->{name} ($target->{id})...");
        my ($pod_name, $target_pod_information) = generate_pod_information_for_target(
            $experiment_name,
            $subject,
            $version,
            $target,
            $options
        );

        $id_to_pod_name_and_target->{$target->{id}} = {
            pod_name    => $pod_name,
            target_name => $target->{name}
        };
        $pod_information->{$pod_name} = $target_pod_information;

        $i++;
        print "\n";
    }

    $log->info("Preparing to create and run kubernetes pods for targets...");

    my $subject_directory = utils::get_subject_directory($experiment_name, $subject, $version);
    my $nfs_subject_directory = utils::get_nfs_subject_directory($experiment_name, $subject, $version);
    my $id_to_pod_name_and_target_file = "$nfs_subject_directory/results/$run_name/id_to_pod_name_and_target.yml";
    YAML::XS::DumpFile($id_to_pod_name_and_target_file, $id_to_pod_name_and_target);

    $log->info("Getting list of existing pods (so that we don't recreate)...");
    system ("kuboid/scripts/pod_names > /tmp/sandpuppy.existing");

    my $existing_pods = 0;
    $i = 1;
    foreach my $pod_name (sort { $pod_information->{$a}->{sort_key} cmp $pod_information->{$b}->{sort_key} } keys %{$pod_information}) {
        my $target_id = $pod_information->{$pod_name}->{target_id};
        my $startup_script = $pod_information->{$pod_name}->{startup_script};
        my $startup_script_name = $pod_information->{$pod_name}->{startup_script_name};
        my $create_command = $pod_information->{$pod_name}->{create_command};
        my $resume_command = $pod_information->{$pod_name}->{resume_command};

        # Check to see if the pod already exists. If it does, we don't want to create it
        system("kubectl get pod $pod_name >/dev/null 2>&1");
        if ($? != 0) {
            $log->info("[$i/$num_targets] Writing out startup script for pod $pod_name (target $target_id)...");

            open my $TARGET_SCRIPT, ">", "$nfs_subject_directory/$startup_script_name";
            print $TARGET_SCRIPT $startup_script;
            close $TARGET_SCRIPT;

            system "chmod 755 $nfs_subject_directory/$startup_script_name";

            $log->info("[$i/$num_targets] Writing out pod-creation script.");

            open my $POD_CREATION_SCRIPT, ">", "$subject_directory/$startup_script_name.create";
            print $POD_CREATION_SCRIPT "$create_command\n";
            close $POD_CREATION_SCRIPT;

            system "chmod 755 $subject_directory/$startup_script_name.create";

            $log->info("[$i/$num_targets] Writing out pod-resumption script.");

            open my $POD_RESUMPTION_SCRIPT, ">", "$subject_directory/$startup_script_name.resume";
            print $POD_RESUMPTION_SCRIPT "$resume_command\n";
            close $POD_RESUMPTION_SCRIPT;

            system "chmod 755 $subject_directory/$startup_script_name.resume";

            if (!$options->{resume}) {
                $log->info("[$i/$num_targets] Creating pod $pod_name for target $target_id");
                system $create_command;
                if ($? != 0) {
                    $log->error("[$i/$num_targets] Creating pod failed: $!");
                }
            } else {
                $log->info("[$i/$num_targets] Resuming pod $pod_name for target $target_id");
                system $resume_command;
                if ($? != 0) {
                    $log->error("[$i/$num_targets] Resuming pod failed: $!");
                }
            }
        } else {
            $log->info("[$i/$num_targets] Skipping existing pod $pod_name for target $target_id");
            $existing_pods++;
        }

        print "\n";
        $i++;
    }

    my $requested_pods = (scalar @{$targets}) - $existing_pods;
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

sub sandpuppy_vanilla_fuzz {
    my $experiment_name = $_[0];
    my $subject = $_[1];
    my $version = $_[2];
    my $options = $_[3];

    my $run_name = $options->{run_name};
    my $id_to_pod_name_and_target = {};

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

    $log->info("Vanilla AFL fuzzing using kubernetes requested.\n");

    initialize_nfs_subject_directory($experiment_name, $subject, $version, $run_name);

    $log->info("Copying $main_target->{binary_context} ($main_target->{id}) files...");
    copy_target_files_to_nfs($experiment_name, $subject, $version, $main_target);
    print "\n";

    $log->info("Generating pod information for $main_target->{name} ($main_target->{id})...");
    my ($pod_name, $target_pod_information) = generate_pod_information_for_target(
        $experiment_name,
        $subject,
        $version,
        $main_target,
        $options
    );
    print "\n";

    $id_to_pod_name_and_target->{$main_target->{id}} = {
        pod_name    => $pod_name,
        target_name => $main_target->{name}
    };

    my $subject_directory = utils::get_subject_directory($experiment_name, $subject, $version);
    my $nfs_subject_directory = utils::get_nfs_subject_directory($experiment_name, $subject, $version);
    my $id_to_pod_name_and_target_file = "$nfs_subject_directory/results/$run_name/id_to_pod_name_and_target.yml";
    YAML::XS::DumpFile($id_to_pod_name_and_target_file, $id_to_pod_name_and_target);

    my $startup_script = $target_pod_information->{startup_script};
    my $startup_script_name = $target_pod_information->{startup_script_name};
    my $create_command = $target_pod_information->{create_command};

    $log->info("Writing out startup script for pod $pod_name (target $main_target->{id})...");

    open my $TARGET_SCRIPT, ">", "$nfs_subject_directory/$startup_script_name";
    print $TARGET_SCRIPT $startup_script;
    close $TARGET_SCRIPT;

    system "chmod 755 $nfs_subject_directory/$startup_script_name";

    $log->info("Writing out pod creation script for pod $pod_name (target $main_target->{id})...");

    open my $POD_CREATION_SCRIPT, ">", "$subject_directory/$startup_script_name.create";
    print $POD_CREATION_SCRIPT "$create_command\n";
    close $POD_CREATION_SCRIPT;

    system "chmod 755 $subject_directory/$startup_script_name.create";

    #if (1) {
    #    exit(0);
    #}

    $log->info("Creating pod $pod_name for target $main_target->{id}");
    system $create_command;
    if ($? != 0) {
        $log->error("Creating pod failed: $!");
    }
}

sub build_sandpuppy_targets {
    my $experiment_name = $_[0];
    my $subject = $_[1];
    my $version = $_[2];
    my $options = $_[3];

    my $subject_directory = utils::get_subject_directory($experiment_name, $subject, $version);
    my $results_dir = "$subject_directory/results";
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
        scalar @{$interesting_variables->{max2}} == 0 &&
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
            foreach my $slot_size (1) {#, 4) {
            #foreach my $slot_size (1, 4, 8, 16, 32, 64) {
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

    # We combine all the grouped targets above into a single array.
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

sub copy_target_files_to_nfs {
    my $experiment_name = $_[0];
    my $subject = $_[1];
    my $version = $_[2];
    my $target = $_[3];

    my $nfs_subject_directory = utils::get_nfs_subject_directory($experiment_name, $subject, $version);
    my $nfs_target_binary_directory = "$nfs_subject_directory/binaries/$target->{binary_context}";
    if (! -e -d $nfs_target_binary_directory) {
        make_path($nfs_target_binary_directory);
    }

    my $subject_directory = utils::get_subject_directory($experiment_name, $subject, $version);
    my $target_binary_directory = "$subject_directory/binaries/$target->{binary_context}";
    my @target_files = `find "$target_binary_directory" -type f | sed -e 's,^.*/,,'`;
    foreach my $target_file (@target_files) {
        chomp($target_file);

        my $target_file_path = "$target_binary_directory/$target_file";
        my $nfs_target_file_path = "$nfs_target_binary_directory/$target_file";

        if (-e -f $nfs_target_file_path) {
            my $ctime_local_target_file = stat($target_file_path)->ctime;
            my $ctime_nfs_target_file = stat($nfs_target_file_path)->ctime;

            if ($ctime_nfs_target_file >= $ctime_local_target_file) {
                $log->info("  Not copying $target_file because it already exists on the NFS and is newer.");
            } else {
                $log->info("  Copying $target_file to the NFS as it is newer than the existing one..");
                system "cp $target_file_path $nfs_target_file_path";
            }
        } else {
            $log->info("  Copying $target_file to the NFS.");
            system "cp $target_file_path $nfs_target_file_path";
        }
    }
}

sub generate_pod_information_for_target {
    my $experiment_name = $_[0];
    my $subject = $_[1];
    my $version = $_[2];
    my $target = $_[3];
    my $options = $_[4];

    my $is_main_target = ($target->{name} =~ /$SANDPUPPY_MAIN_TARGET_NAME$/);
    my $full_subject = $subject . ($version ? "-$version" : "");
    my $run_name = $options->{run_name};
    my $asan_suffix = ($options->{use_asan} ? "-asan" : "");

    my $pod_name;
    my $templated_pod_name;
    if ($is_main_target == 1) {
        $pod_name = "$experiment_name-$full_subject-$run_name--$target->{id}$asan_suffix";
        $templated_pod_name = "$experiment_name-$full_subject-\$RUN_NAME--$target->{id}$asan_suffix";
    } else {
        $pod_name = $target->{waypoints} eq "vvmax" ?
            "$experiment_name-$full_subject-$run_name--$target->{id}$asan_suffix" :
            "$experiment_name-$full_subject-$run_name--$target->{id}-$target->{waypoints}$asan_suffix";
        $templated_pod_name = $target->{waypoints} eq "vvmax" ?
            "$experiment_name-$full_subject-\$RUN_NAME--$target->{id}$asan_suffix" :
            "$experiment_name-$full_subject-\$RUN_NAME--$target->{id}-$target->{waypoints}$asan_suffix";
    }

    $pod_name =~ s/[\._]/-/g; # pod names have restrictions

    my $startup_script = utils::generate_startup_script(
        $experiment_name,
        $subject,
        $version,
        $templated_pod_name,
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
                parallel_fuzz_mode => ($is_main_target ? "parent" : "child"),
                run_name           => $run_name,
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
                parallel_fuzz_mode => ($is_main_target ? "parent" : "child"),
                run_name           => $run_name,
                resume             => 1
                #exit_when_done      => 1
            }
        )
    );

    my $container_nfs_subject_directory = utils::get_container_nfs_subject_directory($experiment_name, $subject, $version);
    my $pod_command = "$container_nfs_subject_directory/$target->{id}.$run_name $run_name";
    return $pod_name, {
        target_id           => $target->{id},
        startup_script      => $startup_script,
        startup_script_name => "$target->{id}.$run_name",
        create_command      => "kuboid/scripts/pod_create -n \"$pod_name\" -s /tmp/sandpuppy.existing -i vivin/sandpuppy $pod_command",
        resume_command      => "kuboid/scripts/pod_create -n \"$pod_name\" -s /tmp/sandpuppy.existing -i vivin/sandpuppy $pod_command resume",
        sort_key            => ($is_main_target ? "a" : $target->{name}) # "a" so that main target is always first
    };
}

sub can_resume {
    my $experiment_name = $_[0];
    my $subject = $_[1];
    my $version = $_[2];

    my $subject_directory = utils::get_subject_directory($experiment_name, $subject, $version);
    my $results_dir = "$subject_directory/results";
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