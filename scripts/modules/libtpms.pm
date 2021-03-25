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
    my $binary_context = $_[3];
    my $waypoints = $_[4];
    my $additional_clang_args = $_[5];

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

    my $use_asan = ($binary_context =~ /asan/);
    if ($use_asan) {
        $ENV{"AFL_USE_ASAN"} = 1;
    }

    if ($waypoints ne "none") {
        $ENV{"WAYPOINTS"} = $waypoints;
        system ("autoreconf --verbose --force --install && CC=\"$build_command $additional_clang_args\" ./configure --with-openssl --with-tpm2 && make -j12");
    } else {
        system ("autoreconf --verbose --force --install && CC=\"$build_command\" ./configure --with-openssl --with-tpm2 && make -j12");
    }

    delete $ENV{"WAYPOINTS"};

    if ($? != 0) {
        die "Make failed";
    }

    my $workspace = "$BASEWORKSPACEPATH/$experiment_name/$subject";

    my $binary_base = "$workspace/binaries";
    my $binary_dir =  "$binary_base/$binary_context";
    my $binary_name = "readtpmc";
    utils::create_binary_dir_and_backup_existing($binary_dir, $binary_name);

    chdir $libtpms_base_dir;

    $log->info("Building readtpmc..");

    system ("$build_command $libtpms_resources/readtpmc.c -I$libtpms_src_dir/include -ltpms -L$libtpms_src_dir/src/.libs -Wl,-rpath,$libtpms_src_dir/src/.libs -o $binary_dir/$binary_name");
    if ($? != 0) {
        die "Building readtpmc failed";
    }

    delete $ENV{"AFL_USE_ASAN"};
}

sub fuzz {
    my $experiment_name = $_[0];
    my $subject = $_[1];
    my $version = $_[2];
    my $exec_context = $_[3];
    my $waypoints = $_[4];
    my $binary_context = $_[5];
    my $options = $_[6];

    my $fuzz_command = utils::build_fuzz_command(
        $experiment_name,
        $subject,
        $version,
        $exec_context,
        $waypoints,
        $binary_context,
        {
            binary_name          => "readtpmc",
            resume               => $options->{resume},
            use_asan             => $binary_context =~ /asan/ ? 1 : 0,
            hang_timeout         => $waypoints =~ /vvdump/ ? "60000+" : 0,
            non_deterministic    => 1,
            seeds_directory      => "$RESOURCES/seeds/libtpms",
            dictionary_file      => 0,
            binary_arguments     => "\@\@",
            sync_directory       => $options->{sync_directory},
            parallel_fuzz_mode   => $options->{parallel_fuzz_mode}
        }
    );

    my $pid = fork;
    return $pid if $pid;

    # Need to run in shell using exec otherwise it runs it as sh -c $fuzz_command and the pid we get is of sh. So when
    # we try to kill it, it doesn't work.
    exec "exec $fuzz_command";
}

1;
