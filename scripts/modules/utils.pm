package utils;

use strict;
use warnings;
use Log::Simple::Color;
use File::Path qw(make_path);

my $log = Log::Simple::Color->new;
my $BASEPATH = glob "~/Projects/phd";
my $BASEWORKSPACEPATH = "$BASEPATH/workspace";
my $TOOLS = "$BASEPATH/tools";
my $RESOURCES = "$BASEPATH/resources";
my $SUBJECTS = "$BASEPATH/subjects";

sub create_binary_dir_and_backup_existing {
    my $binary_dir = $_[0];
    my $binary_name = $_[1];

    my $binary = "$binary_dir/$binary_name";
    if (-d $binary_dir and -e $binary) {
        my $result = `find $binary_dir -type f -name "*backup[0-9]" | sed -e 's,^.*backup,,' | sort -nr | head -1`;
        if ($result eq "") {
            $result = -1;
        }

        my $new_version = ++$result;

        $log->info("Backing up existing binary to backup version $new_version");
        system ("cp $binary $binary_dir/$binary_name.backup$new_version");
    } elsif (! -d $binary_dir) {
        make_path($binary_dir);
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

sub build_fuzz_command {
    my $experiment_name = $_[0];
    my $subject = $_[1];
    my $version = $_[2];
    my $exec_context = $_[3];
    my $waypoints = $_[4];
    my $binary_context = $_[5];
    my $options = $_[6];
    my $binary_name = $options->{binary_name};
    my $resume = $options->{resume};
    my $use_asan = $options->{use_asan};
    my $hang_timeout = $options->{hang_timeout};
    my $non_deterministic = $options->{non_deterministic};
    my $seeds_directory = $options->{seeds_directory};
    my $dictionary_file = $options->{dictionary_file};
    my $binary_arguments = $options->{binary_arguments};
    my $sync_directory = $options->{sync_directory};
    my $parallel_fuzz_mode = $options->{parallel_fuzz_mode};

    if (($sync_directory && !$parallel_fuzz_mode) || (!$sync_directory && $parallel_fuzz_mode)) {
        die "If sync_directory is provided, parallel_fuzz_mode must be provided and vice-versa";
    }

    my $workspace = "$BASEWORKSPACEPATH/$experiment_name/$subject" . ($version ? "-$version" : "");
    my $results_base = "$workspace/results";
    my $results_dir = !$sync_directory ? "$results_base/$exec_context" : "$results_base/$sync_directory";

    if (!$resume) {
        create_results_dir_and_backup_existing($results_base, $exec_context);
    } elsif (! -d $results_dir) {
        die "Cannot resume because cannot find results dir at $results_dir";
    }

    my $binary = "$workspace/binaries/$binary_context/$binary_name";
    if (! -e $binary) {
        die "Could not find binary for binary context $binary_context at $binary";
    }

    my $FUZZ_FACTORY = "$TOOLS/FuzzFactory";
    my $fuzz_command = "$FUZZ_FACTORY/afl-fuzz";
    if ($waypoints ne "none") {
        $fuzz_command .= " -p";
    }

    if ($resume) {
        $fuzz_command .= " -i-"
    } elsif ($seeds_directory) {
        $fuzz_command .= " -i $seeds_directory";

        if ($dictionary_file) {
            $fuzz_command .= " -x $dictionary_file"
        }
    } else {
        die "No seeds directory provided in options argument!";
    }

    my $banner = $subject . ($version ? "-$version" : "") . "-$experiment_name-$exec_context";
    $fuzz_command .= " -o $results_dir -T \"$banner\"";

    if ($sync_directory) {
        $fuzz_command .= (($parallel_fuzz_mode eq "parent" ? " -M " : " -S ") . "\"$exec_context\"");

        # During parallel fuzzing we will monitor these instances on our own, so redirect STDOUT and STDERR to /dev/null
        open STDOUT, ">",  "/dev/null" or die "$0: open: $!";
        open STDERR, ">&", \*STDOUT    or exit 1;
    }

    if ($use_asan) {
        $ENV{"ASAN_OPTIONS"} = "abort_on_error=1:detect_leaks=0:symbolize=0:exitcode=86:allocator_may_return_null=1";
        $fuzz_command .= " -m 15000"; # Hard to estimate on 64 bit; let's set it to 15 gig.
    }

    if ($hang_timeout) {
        $fuzz_command .= " -t $hang_timeout";
    }

    if ($non_deterministic) {
        $fuzz_command .= " -d";
    }

    $fuzz_command .= " $binary";

    # Extra arguments to binary. Can contain @@ to tell AFL to provide input as file name
    if ($binary_arguments) {
        $fuzz_command .= " $binary_arguments";
    }

    return $fuzz_command;
}