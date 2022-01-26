package utils;

use strict;
use warnings FATAL => 'all';
use Log::Simple::Color;
use File::Path qw(make_path);
use List::Util qw(reduce);
use POSIX;

my $log = Log::Simple::Color->new;
my $BASEPATH = glob "~/Projects/phd";
my $BASEWORKSPACEPATH = "$BASEPATH/workspace";
my $TOOLS = "$BASEPATH/tools";

my $SANDPUPPY_SYNC_DIRECTORY = "sandpuppy-sync";

my $ASAN_MEMORY_LIMIT = 1024; #20971586; # Depends on the system. For 64-bit ASAN allocates something ridiculous like 20 TB.

srand(time);

sub get_clang_library_path {
    return "/usr/lib/llvm-10/lib/clang/10.0.0/lib/linux"
}

sub get_clang_asan_dso {
    return get_clang_library_path() . "/libclang_rt.asan-x86_64.so";
}

sub get_clang_asan_static_lib {
    return get_clang_library_path() . "/libclang_rt.asan-x86_64.a";
}

sub get_subject_directory {
    my $experiment_name = $_[0];
    my $subject = $_[1];
    my $version = $_[2];

    return "$experiment_name/$subject" . ($version ? "-$version" : "");
}

sub get_workspace {
    my $experiment_name = $_[0];
    my $subject = $_[1];
    my $version = $_[2];

    return "$BASEWORKSPACEPATH/$experiment_name/$subject" . ($version ? "-$version" : "");
}

sub create_binary_dir {
    my $options = $_[0];
    my $binary_dir = $options->{binary_dir};
    my $artifact_names = $options->{artifact_names};
    my $backup = $options->{backup};

    if (! -d $binary_dir) {
        make_path($binary_dir);
    } else {
        foreach my $artifact_name (@{$artifact_names}) {
            my $artifact = "$binary_dir/$artifact_name";
            if (-e $artifact && $backup) {
                my $result = `find $binary_dir -type f -name "*backup[0-9]" | sed -e 's,^.*backup,,' | sort -nr | head -1`;
                if ($result eq "") {
                    $result = -1;
                }

                my $new_version = ++$result;

                $log->info("Backing up existing binary to backup version $new_version");
                system ("mv $artifact $binary_dir/$artifact_name.backup$new_version");
            }
        }
    }
}

sub create_results_dir_and_backup_existing {
    my $results_base = $_[0];
    my $exec_context = $_[1];

    my $results_dir = "$results_base/$exec_context";
    if (-d $results_dir) {
        my $result = `find $results_base -type d -regex '.*$exec_context.backup[0-9]+' | sed -e 's,^.*backup,,' | sort -nr | head -1`;
        if ($result eq "") {
            $result = -1;
        }

        my $new_version = ++$result;

        $log->info("Backing up existing results directory to backup version $new_version");
        system ("mv $results_dir $results_base/$exec_context.backup$new_version");
    }

    make_path($results_dir);
}

sub build_options_string {
    if (!defined $_[0]) {
        return "";
    }

    my %options = %{$_[0]};
    return reduce { $a . " -$b=\"$options{$b}\"" } "", keys(%options);
}

sub build_fuzz_command {
    my $experiment_name = $_[0];
    my $subject = $_[1];
    my $version = $_[2];
    my $waypoints = $_[3];
    my $binary_context = $_[4];
    my $exec_context = $_[5];
    my $options = $_[6];
    my $binary_name = $options->{binary_name};
    my $async = $options->{async};
    my $resume = $options->{resume};
    my $exit_when_done = $options->{exit_when_done};
    my $preload = $options->{preload};
    my $use_asan = $options->{use_asan};
    my $use_kubernetes = $options->{use_kubernetes};
    my $asan_memory_limit = $options->{asan_memory_limit};
    my $hang_timeout = $options->{hang_timeout};
    my $non_deterministic = $options->{non_deterministic};
    my $no_arithmetic = $options->{no_arithmetic};
    my $no_splicing = $options->{no_splicing};
    my $slow_target = $options->{slow_target};
    my $seeds_directory = $options->{seeds_directory};
    my $dictionary_file = $options->{dictionary_file};
    my $binary_arguments = $options->{binary_arguments};
    my $fuzzer_id = $options->{fuzzer_id};
    my $sync_directory_name = $options->{sync_directory_name};
    my $parallel_fuzz_mode = $options->{parallel_fuzz_mode};

    my %ENV_VARS = ();
    if ($async) {
        $ENV_VARS{AFL_NO_UI} = 1;
    }

    if ($no_arithmetic) {
        $ENV_VARS{AFL_NO_ARITH} = 1;
    }

    if ($no_splicing) {
        $ENV_VARS{AFL_NO_SPLICING} = 1;
    }

    if ($slow_target) {
        $ENV_VARS{AFL_FAST_CAL} = 1;
    }

    if ($exit_when_done) {
        $ENV_VARS{AFL_EXIT_WHEN_DONE} = 1;
    }

    if ($preload) {
        $ENV_VARS{AFL_PRELOAD} = $preload;
    }

    if (!$use_kubernetes &&
        ($fuzzer_id || $sync_directory_name || $parallel_fuzz_mode) &&
        (!$fuzzer_id || !$sync_directory_name || !$parallel_fuzz_mode)) {
        die "If any of fuzzer_id, sync_directory_name, or parallel_fuzz_mode is provided, all must be provided";
    }

    my $workspace = get_workspace($experiment_name, $subject, $version);
    my $results_base = "$workspace/results";
    my $results_dir;
    if ($use_kubernetes) {
        $results_dir = $parallel_fuzz_mode ? "/out" : "/out/$fuzzer_id";
    } else {
        $results_dir = !$sync_directory_name ? "$results_base/$exec_context" : "$results_base/$sync_directory_name";
    }

    if (!$resume) {
        create_results_dir_and_backup_existing($results_base, $exec_context) if !$fuzzer_id;
    } elsif (! -d $results_dir) {
        die "Cannot resume because cannot find results dir at $results_dir" if !$use_kubernetes;
    }

    my $binary = "$workspace/binaries/$binary_context/$binary_name";
    if (! -e $binary) {
        die "Could not find binary for binary context $binary_context at $binary";
    }

    # If we are using kubernetes then we copy the binary from the shared mount to a local bin directory in the
    # container. So let us run that instead (performance is better).
    if ($use_kubernetes) {
        $binary = "/home/vivin/Projects/phd/bin/$binary_context/$binary_name";
    }

    my $FUZZ_FACTORY = "$TOOLS/FuzzFactory";
    my $fuzz_command = "$FUZZ_FACTORY/afl-fuzz";
    if ($waypoints ne "none") {
        $fuzz_command .= " -p";
    }

    if ($resume) {
        $fuzz_command .= " -i-"
    } elsif ($seeds_directory) {
        my $subdir = ($waypoints eq "vvdump") ? "tracegen" : "fuzz";
        $fuzz_command .= " -i $seeds_directory/$subdir";

        if ($dictionary_file) {
            $fuzz_command .= " -x $dictionary_file"
        }
    } else {
        die "No seeds directory provided in options argument!";
    }

    my $banner = $subject . ($version ? "-$version" : "") . "-$experiment_name-$exec_context";
    $fuzz_command .= " -o $results_dir -T \"$banner\"";

    if ($fuzzer_id && $parallel_fuzz_mode) {
        #$ENV_VARS{AFL_IMPORT_FIRST} = 1;  # disable importing first so that there is initial divergence in search paths
        $fuzz_command .= (($parallel_fuzz_mode eq "parent" ? " -M " : " -S ") . "\"$fuzzer_id\"");
    }

    if ($use_asan) {
        $ENV_VARS{ASAN_OPTIONS} = "abort_on_error=1:detect_leaks=0:symbolize=0:exitcode=86:allocator_may_return_null=1";
        $fuzz_command .= " -m " . ($asan_memory_limit ? $asan_memory_limit : $ASAN_MEMORY_LIMIT); # Hard to estimate on 64 bit; let's set it to 15 gig.
    }

    if ($hang_timeout) {
        $fuzz_command .= " -t $hang_timeout";
    }

    # Only honor request for non-deterministic fuzzing if we are not doing parallel fuzzing.
    if ($non_deterministic && !$fuzzer_id) {
        $fuzz_command .= " -d";
    }

    $fuzz_command .= " -- $binary";

    # Extra arguments to binary. Can contain @@ to tell AFL to provide input as file name
    if (defined $binary_arguments) {
        $fuzz_command .= " $binary_arguments";
    }

    return ($fuzz_command, \%ENV_VARS);
}

sub interleave {
    my @a = @{$_[0]};
    my @b = @{$_[1]};

    my @interleaved = ();
    my ($limit, @c) = (scalar @a < scalar @b) ? (scalar @a, @b) : (scalar @b, @a);
    for (my $i = 0; $i < $limit; $i ++) {
        push @interleaved, ($a[$i], $b[$i]);
    }

    push @interleaved, @c[$limit..(scalar @c - 1)];
    return \@interleaved;
}

sub chunk {
    my @array = @{$_[0]};
    my $chunk_size = $_[1];

    my $num_chunks = floor(scalar @array / $chunk_size);
    my @chunks = ();
    for (my $i = 0; $i < $num_chunks; $i++) {
        my $start = $i * $chunk_size;
        my $end = ($start + $chunk_size) - 1;
        my @chunk = @array[$start..$end];
        push @chunks, \@chunk;
    }

    my $remaining = scalar @array % $chunk_size;
    if ($remaining > 0) {
        my $start = $num_chunks * $chunk_size;
        my $end = $start + ($remaining - 1);
        my @chunk = @array[$start..$end];
        push @chunks, \@chunk;
    }

    return \@chunks;
}

sub merge {
    my %source = %{$_[0]};
    my %destination = %{$_[1]};

    foreach my $key (keys(%source)) {
        $destination{$key} = $source{$key};
    }

    return \%destination;
}

sub get_random_fuzzer_id {
    chomp(my $id = `petname -w 3`);
    return $id;
}

sub generate_target_script {
    my $experiment_name = $_[0];
    my $subject = $_[1];
    my $version = $_[2];
    my $pod_name = $_[3];
    my $target = $_[4];
    my $options = $_[5];
    my $fuzz_command = $_[6];
    my $fuzz_command_with_resume = $_[7];

    my $subject_directory = get_subject_directory($experiment_name, $subject, $version);
    my $container_nfs_subject_directory = "/private-nfs/vivin/$subject_directory";
    my $remote_nfs_subject_directory = "/media/2tb/phd-workspace/nfs/vivin/$subject_directory";

    my $random_initial_sleep = int(rand(30)) + 1;
    return <<~"HERE";
    #!/bin/bash

    if [[ \$# -lt 1 ]]; then
      echo "\$0 <run-name> [resume]"
      exit 1
    fi

    RUN_NAME=\$1
    RESUME=\$2

    NUM_CORES=\$(lscpu | grep -e "^CPU(s):" | sed -e 's,^.* ,,')
    AVAILABLE_CORES=\$(( NUM_CORES - 2 )) # One for AFL and one for sync() running in the background

    SYNC_DELAY=300
    ATTEMPTS_BEFORE_FULL_SYNC=6

    DELAY=0.1
    EXPONENT=2

    log () {
      echo -e "\\e[1m\\e[32m[\$(date -u)]\\e[0m \$1"
    }

    warn () {
      log "\\e[33m\$1\\e[0m"
    }

    sync_current_target_to_share() {
      remote_nfs_sync_directory="$remote_nfs_subject_directory/results/\$RUN_NAME/$SANDPUPPY_SYNC_DIRECTORY"

      rsync -az -e "ssh -S '/home/vivin/.ssh/ctl/$target->{id}\@%h:%p'" \\
            /out/$target->{id} vivin\@vivin.is-a-geek.net:"\$remote_nfs_sync_directory" 2> /tmp/rsync.err
    }

    sync_current_target_from_share() {
      remote_nfs_target_directory="$remote_nfs_subject_directory/results/\$RUN_NAME/$SANDPUPPY_SYNC_DIRECTORY/$target->{id}"

      rsync -az -e "ssh -S '/home/vivin/.ssh/ctl/$target->{id}\@%h:%p'" \\
            vivin\@vivin.is-a-geek.net:"\$remote_nfs_target_directory" /out 2> /tmp/rsync.err
    }

    sync_target_inputs_from_share() {
      target=\$1
      remote_nfs_target_directory="$remote_nfs_subject_directory/results/\$RUN_NAME/$SANDPUPPY_SYNC_DIRECTORY/\$target"

      rsync -az -e "ssh -S '/home/vivin/.ssh/ctl/$target->{id}\@%h:%p'" \\
            --include="fuzzer_stats" --include="queue/" \\
            --exclude="hangs*/" --exclude="crashes*/" --exclude=".synced/" --exclude="fuzz_bitmap" \\
            --exclude=".cur_input" --exclude="plot_data" --exclude="fuzzfactory.log" \\
            vivin\@vivin.is-a-geek.net:"\$remote_nfs_target_directory" /out 2> /tmp/rsync.err
    }

    sync_with_retry() {
      sync_function=\$1
      shift

      attempt=1
      \$sync_function \$\@
      while [[ "\$?" -ne 0 ]]
      do
        calculated_delay=\$(perl -e "print \$DELAY * (\$EXPONENT ** \$attempt)")
        warn "\$sync_function failed."
        cat /tmp/rsync.err
        warn "Retrying after sleeping for \$calculated_delay seconds..."
        sleep "\$calculated_delay"

        attempt=\$(( attempt + 1 ))
        \$sync_function \$\@
      done
    }

    sync() {
      # Sleep first before we start syncing. This gives AFL time to start up and produce some results.
      sleep "\$SYNC_DELAY"

      count=0
      while :
      do
        # Start control SSH session
        ssh -nNf -M -S "/home/vivin/.ssh/ctl/$target->{id}\@%h:%p" -o StrictHostKeyChecking=no -i /home/vivin/sandpuppy-pod-key \\
            vivin\@vivin.is-a-geek.net

        # First copy this target's results over to the share
        log "Copying target results to share"
        sync_with_retry sync_current_target_to_share
        log "Done copying target results to share"

        # If 30 minutes have elapsed let's sync results from the other targets
        if [[ "\$count" -eq "\$ATTEMPTS_BEFORE_FULL_SYNC" ]]; then
          while IFS="" read -r target || [ -n "\$target" ]
          do
            container_nfs_target_directory="$container_nfs_subject_directory/results/\$RUN_NAME/$SANDPUPPY_SYNC_DIRECTORY/\$target"
            if [[ -d "\$container_nfs_target_directory" ]]; then
              log "Syncing \$target inputs"
              sync_with_retry sync_target_inputs_from_share "\$target"
              log "Done syncing \$target inputs"

              sleep "\$DELAY"
            else
              log "No existing results found for target \$target"
            fi
          done < /out/targets

          count=0
        fi

        # End control SSH session
        ssh -O exit -S "/home/vivin/.ssh/ctl/$target->{id}\@%h:%p" vivin\@vivin.is-a-geek.net

        sleep "\$SYNC_DELAY"
        count=\$(( count + 1 ))
      done
    }

    echo "Experiment: $experiment_name"
    echo "Subject: ${\($subject . ($version ? "-$version" : ""))}"
    echo "Run Name: \$RUN_NAME"
    echo "Target name: $target->{name}"
    echo "Pod name: $pod_name"

    ln -sf /private-nfs/vivin /home/vivin/Projects/phd/workspace
    mkdir -p /home/vivin/Projects/phd/bin
    mkdir -p $container_nfs_subject_directory/results/\$RUN_NAME/$SANDPUPPY_SYNC_DIRECTORY
    mkdir -p /home/vivin/.ssh/ctl
    cp /private-nfs/vivin/sandpuppy-pod-key /home/vivin/sandpuppy-pod-key

    # Check to see if the list of other targets exist. If not, make it. We use this list when syncing.
    if [[ ! -f "/out/targets" ]]; then
      grep -e "^[^- ]" $container_nfs_subject_directory/results/\$RUN_NAME/id_to_pod_name_and_target.yml | sed -e 's,:,,' | grep -v "$target->{id}" > /out/targets
    fi

    # We don't want pods slamming the SSH server at the same time on resume or sync, so we will sleep first before we
    # do anything. This value is generated randomly.
    log "Sleeping for $random_initial_sleep seconds before starting..."
    sleep $random_initial_sleep

    if [[ -z "\$RESUME" ]]; then
      date +%s >"$container_nfs_subject_directory/results/\$RUN_NAME/$SANDPUPPY_SYNC_DIRECTORY/start_ts"
    else
      # Start control SSH session
      ssh -nNf -M -S "/home/vivin/.ssh/ctl/$target->{id}\@%h:%p" -o StrictHostKeyChecking=no -i /home/vivin/sandpuppy-pod-key \\
          vivin\@vivin.is-a-geek.net

      # We are resuming, so first copy over this target's results directory, and then the queues from other targets
      log "Copying previous results from share into local results directory"
      sync_with_retry sync_current_target_from_share
      log "Done copying previous results from share into local results directory"

      while IFS="" read -r target || [ -n "\$target" ]
      do
        container_nfs_target_directory="$container_nfs_subject_directory/results/\$RUN_NAME/$SANDPUPPY_SYNC_DIRECTORY/\$target"
        if [[ -d "\$container_nfs_target_directory" ]]; then
          log "Syncing existing inputs for \$target"
          sync_with_retry sync_target_inputs_from_share "\$target"
          log "Done syncing existing inputs for \$target"

          sleep "\$DELAY"
        else
          log "No existing results found for target \$target"
        fi
      done < /out/targets

      # End control SSH session
      ssh -O exit -S "/home/vivin/.ssh/ctl/$target->{id}\@%h:%p" vivin\@vivin.is-a-geek.net
    fi

    # Copy the binary and any other files in the nfs binary directory to a local directory
    cp -r "$container_nfs_subject_directory/binaries/$target->{binary_context}" /home/vivin/Projects/phd/bin

    # Since we don't copy over the symlinks created for binary directories with colons (we do this because when linking
    # the linker has issues with paths containing colons) dynamically linked binaries have issues finding their shared
    # library. So we will create a symlink to the local binary directory and set LD_LIBRARY_PATH to it.
    ln -s "/home/vivin/Projects/phd/bin/$target->{binary_context}" /home/vivin/lib
    export LD_LIBRARY_PATH=/home/vivin/lib

    cd /home/vivin/Projects/phd
    sync &
    SYNC_PID=\$!

    if [[ -z "\$RESUME" ]]; then
      $fuzz_command
    else
      $fuzz_command_with_resume
    fi

    kill \$SYNC_PID >/dev/null 2>&1
    HERE
}

# Single target version of the above. Meaning it fuzzes a single target and doesn't try to sync results. Really only
# used for the main target so that we can fuzz with just vanilla AFL.
sub generate_single_target_script {
    my $experiment_name = $_[0];
    my $subject = $_[1];
    my $version = $_[2];
    my $pod_name = $_[3];
    my $target = $_[4];
    my $options = $_[5];
    my $fuzz_command = $_[6];
    my $fuzz_command_with_resume = $_[7];

    my $subject_directory = get_subject_directory($experiment_name, $subject, $version);
    my $container_nfs_subject_directory = "/private-nfs/vivin/$subject_directory";
    my $remote_nfs_subject_directory = "/media/2tb/phd-workspace/nfs/vivin/$subject_directory";

    my $random_initial_sleep = int(rand(30)) + 1;
    return <<~"PLAIN";
    #!/bin/bash

    if [[ \$# -lt 1 ]]; then
      echo "\$0 <run-name> [resume]"
      exit 1
    fi

    RUN_NAME=\$1
    RESUME=\$2

    NUM_CORES=\$(lscpu | grep -e "^CPU(s):" | sed -e 's,^.* ,,')
    AVAILABLE_CORES=\$(( NUM_CORES - 2 )) # One for AFL and one for sync() running in the background

    SYNC_DELAY=300
    ATTEMPTS_BEFORE_FULL_SYNC=6

    DELAY=0.1
    EXPONENT=2

    log () {
      echo -e "\\e[1m\\e[32m[\$(date -u)]\\e[0m \$1"
    }

    warn () {
      log "\\e[33m\$1\\e[0m"
    }

    sync_current_target_to_share() {
      remote_nfs_sync_directory="$remote_nfs_subject_directory/results/\$RUN_NAME/$SANDPUPPY_SYNC_DIRECTORY"

      rsync -az -e "ssh -S '/home/vivin/.ssh/ctl/$target->{id}\@%h:%p'" \\
            /out/$target->{id} vivin\@vivin.is-a-geek.net:"\$remote_nfs_sync_directory" 2> /tmp/rsync.err
    }

    sync_current_target_from_share() {
      remote_nfs_target_directory="$remote_nfs_subject_directory/results/\$RUN_NAME/$SANDPUPPY_SYNC_DIRECTORY/$target->{id}"

      rsync -az -e "ssh -S '/home/vivin/.ssh/ctl/$target->{id}\@%h:%p'" \\
            vivin\@vivin.is-a-geek.net:"\$remote_nfs_target_directory" /out 2> /tmp/rsync.err
    }

    sync_with_retry() {
      sync_function=\$1
      shift

      attempt=1
      \$sync_function \$\@
      while [[ "\$?" -ne 0 ]]
      do
        calculated_delay=\$(perl -e "print \$DELAY * (\$EXPONENT ** \$attempt)")
        warn "\$sync_function failed."
        cat /tmp/rsync.err
        warn "Retrying after sleeping for \$calculated_delay seconds..."
        sleep "\$calculated_delay"

        attempt=\$(( attempt + 1 ))
        \$sync_function \$\@
      done
    }

    sync() {
      # Sleep first before we start syncing. This gives AFL time to start up and produce some results.
      sleep "\$SYNC_DELAY"

      count=0
      while :
      do
        # Start control SSH session
        ssh -nNf -M -S "/home/vivin/.ssh/ctl/$target->{id}\@%h:%p" -o StrictHostKeyChecking=no -i /home/vivin/sandpuppy-pod-key \\
            vivin\@vivin.is-a-geek.net

        # First copy this target's results over to the share
        log "Copying target results to share"
        sync_with_retry sync_current_target_to_share
        log "Done copying target results to share"

        # End control SSH session
        ssh -O exit -S "/home/vivin/.ssh/ctl/$target->{id}\@%h:%p" vivin\@vivin.is-a-geek.net

        sleep "\$SYNC_DELAY"
        count=\$(( count + 1 ))
      done
    }

    echo "Experiment: $experiment_name"
    echo "Subject: ${\($subject . ($version ? "-$version" : ""))}"
    echo "Run Name: \$RUN_NAME"
    echo "Target name: $target->{name}"
    echo "Pod name: $pod_name"

    ln -sf /private-nfs/vivin /home/vivin/Projects/phd/workspace
    mkdir -p /home/vivin/Projects/phd/bin
    mkdir -p $container_nfs_subject_directory/results/\$RUN_NAME/$SANDPUPPY_SYNC_DIRECTORY
    mkdir -p /home/vivin/.ssh/ctl
    cp /private-nfs/vivin/sandpuppy-pod-key /home/vivin/sandpuppy-pod-key

    log "Sleeping for $random_initial_sleep seconds before starting..."
    sleep $random_initial_sleep

    if [[ -z "\$RESUME" ]]; then
      date +%s >"$container_nfs_subject_directory/results/\$RUN_NAME/$SANDPUPPY_SYNC_DIRECTORY/start_ts"
    else
      # Start control SSH session
      ssh -nNf -M -S "/home/vivin/.ssh/ctl/$target->{id}\@%h:%p" -o StrictHostKeyChecking=no -i /home/vivin/sandpuppy-pod-key \\
          vivin\@vivin.is-a-geek.net

      # We are resuming, so first copy over this target's results directory
      log "Copying previous results from share into local results directory"
      sync_with_retry sync_current_target_from_share
      log "Done copying previous results from share into local results directory"

      # End control SSH session
      ssh -O exit -S "/home/vivin/.ssh/ctl/$target->{id}\@%h:%p" vivin\@vivin.is-a-geek.net
    fi

    # Copy the binary and any other files in the nfs binary directory to a local directory
    cp -r "$container_nfs_subject_directory/binaries/$target->{binary_context}" /home/vivin/Projects/phd/bin

    # Since we don't copy over the symlinks created for binary directories with colons (we do this because when linking
    # the linker has issues with paths containing colons) dynamically linked binaries have issues finding their shared
    # library. So we will create a symlink to the local binary directory and set LD_LIBRARY_PATH to it.
    ln -s "/home/vivin/Projects/phd/bin/$target->{binary_context}" /home/vivin/lib
    export LD_LIBRARY_PATH=/home/vivin/lib

    cd /home/vivin/Projects/phd
    sync &
    SYNC_PID=\$!

    if [[ -z "\$RESUME" ]]; then
      $fuzz_command
    else
      $fuzz_command_with_resume
    fi

    kill \$SYNC_PID >/dev/null 2>&1
    PLAIN
}