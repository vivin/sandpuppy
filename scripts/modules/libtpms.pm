package libtpms;

use strict;
use warnings;
use Log::Simple::Color;
use File::Path qw(make_path);
use utils;

my $log = Log::Simple::Color->new;
my $BASEPATH = glob "~/Projects/phd";
my $BASEWORKSPACEPATH = "$BASEPATH/workspace";
my $TOOLS = "$BASEPATH/tools";
my $RESOURCES = "$BASEPATH/resources";
my $SUBJECTS = "$BASEPATH/subjects";

sub build {
    my $experiment_name = $_[0];
    my $subject = $_[1];
    my $version = $_[2];
    my $context = $_[3];
    my $waypoints = $_[4];

    my $libtpms_base_dir = "$SUBJECTS/libtpms";
    my $libtpms_src_dir = "$libtpms_base_dir/libtpms-master";
    my $libtpms_resources = "$RESOURCES/archives/libtpms";

    $log->info("Checking if source is already unpacked...");
    if (! -d $libtpms_src_dir) {
        $log->info("Source is not unpacked. Unpacking...");

        my $libtpms_src = "$libtpms_resources/libtpms-master.zip";
        if (! -f $libtpms_src) {
            die "Could not find libtpms source: $libtpms_src";
        }

        if (! -d $libtpms_base_dir) {
            system ("mkdir -p $libtpms_base_dir 2> /dev/null") == 0
                or die "Failed to create $libtpms_base_dir";
        }

        chdir $libtpms_base_dir;
        system ("unzip $libtpms_src");
    } else {
        $log->info("Source is already unpacked");
    }

    chdir $libtpms_src_dir;

    if (-f "$libtpms_src_dir/Makefile") {
        $log->info("Makefile exists; cleaning.");
        system ("make clean");
    }

    my $FUZZ_FACTORY = "$TOOLS/FuzzFactory";
    my $build_command = "$FUZZ_FACTORY/afl-clang-fast -fno-inline-functions -fno-discard-value-names -fno-unroll-loops";

    my $use_asan = ($context =~ /asan/);
    if ($use_asan) {
        $ENV{"AFL_USE_ASAN"} = 1;
    }

    if ($waypoints ne "none") {
        $ENV{"WAYPOINTS"} = $waypoints;
        system ("autoreconf --verbose --force --install && CC=\"$build_command\" ./configure --with-openssl --with-tpm2 && make -j12");
    } else {
        system ("autoreconf --verbose --force --install && CC=\"$build_command\" ./configure --with-openssl --with-tpm2 && make -j12");
    }

    delete $ENV{"WAYPOINTS"};
    delete $ENV{"AFL_USE_ASAN"};

    if ($? != 0) {
        die "Make failed";
    }

    my $workspace = "$BASEWORKSPACEPATH/$experiment_name/$subject";

    my $binary_base = "$workspace/binaries";
    my $binary_dir =  "$binary_base/$context";
    my $binary_name = "readtpmc";
    utils::create_binary_dir_and_backup_existing($binary_dir, $binary_name);

    chdir $libtpms_base_dir;

    $log->info("Building readtpmc..");

    system ("$build_command $libtpms_resources/readtpmc.c -I$libtpms_src_dir/include -ltpms -L$libtpms_src_dir/src/.libs -Wl,-rpath,$libtpms_src_dir/src/.libs -o $binary_dir/$binary_name");
    if ($? != 0) {
        die "Building readtpmc failed";
    }
}

sub fuzz {
    my $pid = fork;
    return $pid if $pid;

    my $experiment_name = $_[0];
    my $subject = $_[1];
    my $version = $_[2];
    my $exec_context = $_[3];
    my $waypoints = $_[4];
    my $binary_context = $_[5];
    my $resume = $_[6];

    my $workspace = "$BASEWORKSPACEPATH/$experiment_name/$subject";
    my $results_base = "$workspace/results";
    my $results_dir = "$results_base/$exec_context";

    if (!$resume) {
        utils::create_results_dir_and_backup_existing($results_base, $exec_context);
    } elsif (! -d $results_dir) {
        die "Cannot resume because cannot find results dir at $results_dir";
    }

    my $binary = "$workspace/binaries/$binary_context/readtpmc";
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
    } else {
        my $seeds_directory = "$RESOURCES/seeds/libtpms";
        $fuzz_command .= " -i $seeds_directory";
    }

    $fuzz_command .= " -o $results_dir -T \"$subject-$experiment_name-$exec_context\"";

    my $use_asan = ($binary_context =~ /asan/);
    if ($use_asan) {
        $ENV{"ASAN_OPTIONS"} = "abort_on_error=1:detect_leaks=0:symbolize=0:exitcode=86:allocator_may_return_null=1";
        $fuzz_command .= " -m none";
    }

    if ($waypoints =~ /vvdump/) {
        $fuzz_command .= " -t 60000+";
        $fuzz_command .= " -d";
    }

    $fuzz_command .= " $binary \@\@";

    # Need to run in shell using exec otherwise it runs it as sh -c $fuzz_command and the pid we get is of sh. So when
    # we try to kill it, it doesn't work.
    exec "exec $fuzz_command";
}

1;
