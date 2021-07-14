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
my $RESOURCES = "$BASEPATH/resources";
my $SUBJECTS = "$BASEPATH/subjects";

my $ASAN_MEMORY_LIMIT = 1024; #20971586; # Depends on the system. For 64-bit ASAN allocates something ridiculous like 20 TB.

sub get_clang_library_path {
    return "/usr/lib/llvm-10/lib/clang/10.0.0/lib/linux"
}

sub get_clang_asan_dso {
    return get_clang_library_path() . "/libclang_rt.asan-x86_64.so";
}

sub get_clang_asan_static_lib {
    return get_clang_library_path() . "/libclang_rt.asan-x86_64.a";
}

sub get_experiment_subject_directory_structure {
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
        $results_dir = "/out/$fuzzer_id";
    } else {
        $results_dir = !$sync_directory_name ? "$results_base/$exec_context" : "$results_base/$sync_directory_name";
    }

    if (!$resume) {
        create_results_dir_and_backup_existing($results_base, $exec_context) if !$fuzzer_id;
    } elsif (! -d $results_dir) {
        die "Cannot resume because cannot find results dir at $results_dir";
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
    chomp(my $id = `cat /dev/urandom | tr -dc 'a-z0-9' | fold -w 16 | head -n 1`);
    return join "-", ($id =~ m/.{4}/g);
}