package tasks;
use strict;
use warnings;
use Log::Simple::Color;
use File::Path qw(make_path);
use Time::HiRes qw(time);
use POSIX;
use YAML::XS;
use Data::Dumper;

use utils;
use display;
use infantheap;
use rarebug;
use maze;
use libpng;
use readelf;
use libtpms;

sub shutdown {
    display::restore_display();
    die;
}

my $log = Log::Simple::Color->new;

my $BASEPATH = glob "~/Projects/phd";
my $TOOLS = "$BASEPATH/tools";

my $WAYPOINTS_NONE = "none";
my $SANDPUPPY_MAIN_TARGET_NAME = "sandpuppy-main";
my $SANDPUPPY_SYNC_DIRECTORY = "sandpuppy-sync";

my @stats_columns = ("unix_time", "cycles_done", "cur_path", "paths_total", "paths_found", "paths_imported",
    "pending_total", "pending_favs", "map_coverage", "unique_crashes", "unique_hangs", "max_depth", "execs_per_sec");

my $subjects = {
    infantheap => {
        tasks     => {
            build => \&infantheap::build,
            fuzz  => \&infantheap::fuzz,
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

    my $tasks = $subjects->{$subject}->{tasks};
    $tasks->{build}->($experiment_name, $subject, $version, $waypoints, $binary_context, $options);

    chdir $BASEPATH;
}

sub fuzz {
    my $experiment_name = $_[0];
    my $subject = $_[1];
    my $version = $_[2];
    my $waypoints = $_[3];
    my $binary_context = $_[4];
    my $execution_context = $_[5];
    my $options = $_[6];

    my $tasks = $subjects->{$subject}->{tasks};

    # If the waypoints include vvdump, it means that we are capturing variable-value traces. So we have to start up
    # the trace processor to read in those traces.
    if ($waypoints =~ /vvdump/) {
        if ($options->{async}) {
            $log->warning("Ignoring request for asynchronous fuzzing because waypoints include vvdump.");
        }

        $ENV{"__VVD_EXP_NAME"} = $experiment_name;
        $ENV{"__VVD_SUBJECT"} = "$subject-$version";
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
            my $fuzzer_pid = $tasks->{fuzz}->(
                $experiment_name,
                $subject,
                $version,
                $waypoints,
                $binary_context,
                $execution_context,
                {}
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
            my $vvdproc = "unbuffer mvn package && unbuffer java -Xms1G -Xmx4G -jar target/vvdproc.jar 2>&1";
            open my $vvdproc_output, "-|", $vvdproc;
            while (<$vvdproc_output>) {
                print $writer $_;
            }

            exit;
        }
    } else {
        my $fuzzer_pid = $tasks->{fuzz}->(
            $experiment_name,
            $subject,
            $version,
            $waypoints,
            $binary_context,
            $execution_context,
            $options
        );

        if ($options->{async}) {
            return $fuzzer_pid;
        }

        waitpid $fuzzer_pid, 0;
    }
}

sub sandpuppy_fuzz {
    my $experiment_name = $_[0];
    my $subject = $_[1];
    my $version = $_[2];
    my $options = $_[3];

    my $NUM_CORES = 12;
    my $OVERALL_FUZZ_TIME = 43200; # For 12 hours for now...

    # We reserve one core to run the parent fuzzer which we won't shut down until we are completely done.
    # TODO: what does "done" mean? No targets have found any paths after X hours?
    my $AVAILABLE_CORES = $NUM_CORES - 1;

    # Generate variables files and build targets using the output from the analysis phase (which should be stored
    # under the results for the provided execution_context). The analysis phase identifies interesting variables to
    # instrument, so we will build targets that do just that.
    my ($main_target, $targets) = build_sandpuppy_targets(
        $experiment_name,
        $subject,
        $version,
        $options
    );

    # Now we will start parallel fuzzing. First we clear the screen, set up some signal handlers (that restore the
    # terminal to a non-annoying state on shutdown) and then start the parent fuzzer instance.
    display::init_display();
    $SIG{INT} = \&shutdown;
    $SIG{TERM} = \&shutdown;

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
            parallel_fuzz_mode  => "parent"
        }
    );

    my $cycle = 1;
    my $done = 0;
    while (!$done) {
        # If we have more targets than available cores, we cannot fuzz all of them at once. So we chunk the list into
        # sub-lists that are at most AVAILABLE_CORES in size.
        my @target_batches = @{utils::chunk($targets, $AVAILABLE_CORES)};
        my $num_batches = scalar @target_batches;

        # Iterate over each chunk. Spin up child fuzzers. Wait for an hour, then kill them and gather their stats. Once
        # done with all chunks, sort targets by number of paths found in descending order. Then re-chunk and fuzz again.
        # TODO: Figure out when we are "done". Two ways to do this. First way is to keep track of how many paths a
        # TODO: target has found in the last X cycles (would need to maintain cumulative stats). If it has not found
        # TODO: any new paths in the last X cycles, we count it as "finished". Another way is to set an environment
        # TODO: variable that tells AFL to shut down the target fuzzing when done. AFL will check to see if the target
        # TODO: has found any new paths. If it hasn't in a while, it will shut it down. All we need to do at the end
        # TODO: when a chunk is done, is invoke kill 0, PID against the fuzzer processes to see if they are still up.
        # TODO: If any are already down we can count them as "finished". !!!!! will have to filter out targets that are
        # TODO: finished before fuzzing! We can use grep before the map to look for those with finished = 0. But we will
        # TODO: still send all targets when we display stats because we display how many targets are finished. HOWEVER
        # TODO: when CHUNKING, we want to make sure that finished targets are not included. So I think THIS is where we
        # TODO: need to use grep.

        # Fuzz each batch for an hour. Unless there is only one batch, in which case we just fuzz that one batch for the
        # whole $OVERALL_FUZZ_TIME seconds.
        my $BATCH_FUZZ_TIME = $num_batches == 1 ? $OVERALL_FUZZ_TIME : 3600; # Fuzz each batch for one hour.
        my $current_batch = 1;
        foreach my $target_batch (@target_batches) {
            my @fuzzer_pids = map {
                fuzz(
                    $experiment_name,
                    $subject,
                    $version,
                    $_->{waypoints},
                    $_->{binary_context},
                    $_->{execution_context},
                    {
                        async               => 1,
                        fuzzer_id           => $_->{id},
                        sync_directory_name => $SANDPUPPY_SYNC_DIRECTORY,
                        parallel_fuzz_mode  => "child",
                        resume              => $_->{previous_stats} ? 1 : 0
                    }
                )
            } @{$target_batch};

            #my $fuzzer_pid_list = join ", ", @fuzzer_pids;
            #print "Started " . scalar @fuzzer_pids . " child fuzzers: $fuzzer_pid_list\n";

            my $batch_start_time = time();
            while (time() - $batch_start_time < $BATCH_FUZZ_TIME) {
                sleep 1;

                $main_target->{stats} = get_parallel_fuzzer_stats($main_target);
                foreach my $target (@{$target_batch}) {
                    $target->{stats} = get_parallel_fuzzer_stats($target);
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
                )
            }

            foreach my $fuzzer_pid (@fuzzer_pids) {
                kill 'INT', $fuzzer_pid;
            }

            # Get latest stats after killing children because fuzzers may have updated plot_data right before we killed
            # them.
            $main_target->{stats} = get_parallel_fuzzer_stats($main_target);
            foreach my $target (@{$target_batch}) {
                $target->{stats} = get_parallel_fuzzer_stats($target);
            }

            $current_batch++;
        }

        # Sort all targets in descending order based on number of newly found paths.
        my @sorted = sort {
            ($b->{previous_stats} ? $b->{stats}->{paths_found} - $b->{previous_stats}->{paths_found} : $b->{stats}->{paths_found})
                <=>
            ($b->{previous_stats} ? $b->{stats}->{paths_found} - $b->{previous_stats}->{paths_found} : $b->{stats}->{paths_found})
        } @{$targets};
        $targets = \@sorted;

        # Copy current stats as previous stats:
        foreach my $target (@{$targets}) {
            $target->{previous_stats} = eval Dumper($target->{stats});
        }

        $cycle++;
        $done = time() - $overall_start_time > $OVERALL_FUZZ_TIME
    }

    display::restore_display();
    kill 'INT', $parent_fuzzer_pid;
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
    my $unique_hangs = 0;
    my $unique_crashes = 0;
    my $max_depth = 0;
    foreach my $target (@{$targets}) {
        next if !$target->{stats};

        $total_paths += $target->{stats}->{paths_total};
        $paths_imported += $target->{stats}->{paths_imported};
        $paths_found += $target->{stats}->{paths_found};
        $unique_hangs += $target->{stats}->{unique_hangs};
        $unique_crashes += $target->{stats}->{unique_crashes};
        $max_depth = $max_depth < $target->{stats}->{max_depth} ? $target->{stats}->{max_depth} : $max_depth;

        if (!$stats{waypoints}->{$target->{waypoints}}) {
            $stats{waypoints}->{$target->{waypoints}} = {
                count          => 0,
                finished       => 0,
                total_paths    => 0,
                paths_imported => 0,
                paths_found    => 0,
                unique_hangs   => 0,
                unique_crashes => 0,
                max_depth      => 0,
                cur_path       => []
            }
        }

        $stats{waypoints}->{$target->{waypoints}}->{count}++;
        if ($target->{finished}) {
            $stats{waypoints}->{$target->{waypoints}}->{finished}++;
            $finished++;
        }

        $stats{waypoints}->{$target->{waypoints}}->{total_paths} += $target->{stats}->{paths_total};
        $stats{waypoints}->{$target->{waypoints}}->{paths_imported} += $target->{stats}->{paths_imported};
        $stats{waypoints}->{$target->{waypoints}}->{paths_found} += $target->{stats}->{paths_found};
        $stats{waypoints}->{$target->{waypoints}}->{unique_hangs} += $target->{stats}->{unique_hangs};
        $stats{waypoints}->{$target->{waypoints}}->{unique_crashes} += $target->{stats}->{unique_crashes};
        if ($target->{stats}->{max_depth} > $stats{waypoints}->{$target->{waypoints}}->{max_depth}) {
            $stats{waypoints}->{$target->{waypoints}}->{max_depth} = $target->{stats}->{max_depth};
        }
        push @{$stats{waypoints}->{$target->{waypoints}}->{cur_path}}, $target->{stats}->{cur_path};
    }

    $stats{aggregate}->{count} = $count;
    $stats{aggregate}->{finished} = $finished;
    $stats{aggregate}->{total_paths} = $total_paths;
    $stats{aggregate}->{paths_imported} = $paths_imported;
    $stats{aggregate}->{paths_found} = $paths_found;
    $stats{aggregate}->{unique_hangs} = $unique_hangs;
    $stats{aggregate}->{unique_crashes} = $unique_crashes;
    $stats{aggregate}->{max_depth} = $max_depth;

    return \%stats;
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

    my $name_to_id = {};
    my $name_to_id_file = "$results_dir/sandpuppy-target-name-to-id.yml";
    if (-e $name_to_id_file) {
        $name_to_id = YAML::XS::LoadFile($name_to_id_file);
    }

    my $grouped_targets = {
        max  => 0,
        perm => [],
        hash => []
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
        my $id = $name_to_id->{$name} ? $name_to_id->{$name} : utils::get_random_fuzzer_id();
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

    # This is temporary and only for individual binaries like infantheap, maze, and rarebug. These were built directly
    # from the current project root and
    if (scalar @{$interesting_variables->{perm}} > 0) {
        foreach my $variable (@{$interesting_variables->{perm}}) {
            my $name = "sandpuppy-vvperm-$variable";
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
            print $VVPERM "$variable:4\n"; # 4 is amount to shift previous value when calculating permutation key
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

            my $name = "sandpuppy-vvhash-$components1[0]:$components1[1]:$components1[2]:$components1[3],$components2[2]:$components2[3]";
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
            print $VVHASH "$variable1:$components2[2]:$components2[3]\n";
            close $VVHASH;
        }
    }

    # Now we will build binaries using the variables files we generated above. We first build a "plain" version with
    # ASAN enabled and regular AFL instrumentation. This binary will be used in the parent fuzzer instance. We also
    # define a hash like the ones above, for this target. This is something we will return from this function as well
    # so that we can use it later to look up stats for the parent fuzzer instance.
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
        { backup => 0 }
    );

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
    my @targets = @{utils::interleave($grouped_targets->{perm}, $grouped_targets->{hash})};
    unshift @targets, $grouped_targets->{max} if $grouped_targets->{max};

    # Build all the targets!
    foreach my $target (@targets) {
        build(
            $experiment_name,
            $subject,
            $version,
            $target->{waypoints},
            $target->{name} . ($options->{use_asan} ? "-asan" : ""),
            {
                backup                 => 0,
                clang_waypoint_options => {
                    variables_file => $target->{variables_file}
                }
            }
        );
    }

    YAML::XS::DumpFile($name_to_id_file, $name_to_id);
    return $main_target, \@targets;
}

sub get_parallel_fuzzer_stats {
    my $target = $_[0];

    my $workspace = utils::get_workspace($target->{experiment_name}, $target->{subject}, $target->{version});
    my $results_base = "$workspace/results";
    my $results_dir = "$results_base/$SANDPUPPY_SYNC_DIRECTORY/$target->{id}";

    # We will use plot_data instead of fuzzer_stats because plot_data is updated more frequently. But sometimes the
    # fuzzer may not be ready yet and so plot_data may not exist or may be empty.
    if ((! -e "$results_dir/plot_data") || (-z "$results_dir/plot_data")) {
        return $target->{stats} ? $target->{stats} : {};
    }

    # If there are at least two lines in the file, then we have data. This is because the first line is for the header.
    chomp(my $num_lines = `wc -l $results_dir/plot_data | awk '{ print \$1 }'`);
    if ($num_lines > 1) {
        chomp(my $line = `tail -1 $results_dir/plot_data`);
        my @components = split /,\s+/, $line;

        my %stats = map { ($stats_columns[$_] => $components[$_]) } (0..(scalar @stats_columns - 1));

        # When we resume fuzzing a previously-fuzzed target, a new plot_data is created. The very first data point is
        # right after the fuzzer starts, and will have total paths set to whatever the number of initial seeds is. The
        # imported paths from previous sessions don't show up until the next data point. So if the target already has
        # stats, we will return those if there is only one data point in the plot_data file.
        if ($target->{stats} && $num_lines == 2) {
            return $target->{stats};
        }

        return \%stats;
    } elsif ($target->{stats}) {
        return $target->{stats};
    } else {
        return {};
    }
}

1;