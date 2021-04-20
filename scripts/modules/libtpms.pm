package libtpms;

use strict;
use warnings FATAL => 'all';
use Log::Simple::Color;
use File::Path qw(make_path);
use utils;

my $log = Log::Simple::Color->new;
my $BASEPATH = glob "~/Projects/phd";
my $TOOLS = "$BASEPATH/tools";
my $RESOURCES = "$BASEPATH/resources";
my $SUBJECTS = "$BASEPATH/subjects";

sub build {
    my $experiment_name = $_[0];
    my $subject = $_[1];
    my $version = $_[2];
    my $waypoints = $_[3];
    my $binary_context = $_[4];
    my $options = $_[5];

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

    if ($binary_context =~ /-asan/) {
        $ENV{"AFL_USE_ASAN"} = 1;
    }

    if ($waypoints ne "none") {
        $ENV{"WAYPOINTS"} = $waypoints;
    }

    my $clang_waypoint_options = utils::build_options_string($options->{clang_waypoint_options});
    system ("autoreconf --verbose --force --install && CC='$build_command$clang_waypoint_options' ./configure --with-openssl --with-tpm2 && make -j12");
    if ($? != 0) {
        delete $ENV{"WAYPOINTS"};
        delete $ENV{"AFL_USE_ASAN"};

        die "Make failed";
    }

    delete $ENV{"WAYPOINTS"};

    my $workspace = utils::get_workspace($experiment_name, $subject, $version);

    my $binary_base = "$workspace/binaries";
    my $binary_dir =  "$binary_base/$binary_context";
    my $binary_name = "readtpmc";
    my @library_names = (
        "libtpms.so",
        "libtpms.so.0",
        "libtpms.so.0.9.0",
        "libtpms.a",
        "libtpms_tpm2.a",
        "libtpms_tpm12.a"
    );
    my @artifact_names = ($binary_name, @library_names);
    utils::create_binary_dir({
        binary_dir     => $binary_dir,
        artifact_names => \@artifact_names,
        backup         => $options->{backup}
    });

    # Copy the shared libraries into the binary dir because the binary will need to use it. We can't just provide the
    # directory in the source to rpath because then all readtpmc binaries will use the same shared libraries, which is
    # not what we want when we build and fuzz multiple targets.
    foreach my $library_name (@library_names) {
        system ("cp $libtpms_src_dir/src/.libs/$library_name $binary_dir");
    }

    chdir $libtpms_base_dir;

    $log->info("Building readtpmc..");

    # If the binary directory (which we get from the execution context) contains colons then we run into problems when
    # providing it to the linker so that it can find the libtpms libraries that we put there. While no errors are shown
    # while linking, ldd will show that it cannot find the libtpms so file. We could modify the execution context, but
    # that would be kind of confusing. So instead let's just create a symlink to the binary directory, where the symlink
    # is the name of the binary directory, but with colons replaced by dots. We can then provide this to the linker and
    # at runtime the executable can find the so files without issue.
    my $safe_binary_dir = $binary_dir;
    if ($binary_dir =~ /:/) {
        $safe_binary_dir =~ s/:/./g;

        if (! -e $safe_binary_dir) {
            system ("ln -s $binary_dir $safe_binary_dir")
        }
    }

    # Use -Xlinker -rpath <path> instead of -Wl,-rpath,<path> because the latter breaks when paths contain commas.
    system ("$build_command $libtpms_resources/readtpmc.c -I$libtpms_src_dir/include -L$safe_binary_dir -lb64 -ltpms -Xlinker -rpath $safe_binary_dir -o $binary_dir/$binary_name\n");
    if ($? != 0) {
        die "Building readtpmc failed";

        delete $ENV{"AFL_USE_ASAN"};
    }

    delete $ENV{"AFL_USE_ASAN"};
}

sub fuzz {
    my $experiment_name = $_[0];
    my $subject = $_[1];
    my $version = $_[2];
    my $waypoints = $_[3];
    my $binary_context = $_[4];
    my $exec_context = $_[5];
    my $options = $_[6];

    my ($fuzz_command, $ENV_VARS) = utils::build_fuzz_command(
        $experiment_name,
        $subject,
        $version,
        $waypoints,
        $binary_context,
        $exec_context,
        {
            binary_name         => "readtpmc",
            resume              => $options->{resume},
            use_asan            => $binary_context =~ /-asan/ ? 1 : 0,
            preload             => 0, #$binary_context =~ /-asan/ ? utils::get_clang_asan_dso() : 0,
            asan_memory_limit   => 20971597,
            hang_timeout        => $waypoints =~ /vvdump/ ? "60000+" : 0,
            non_deterministic   => 0, #$waypoints =~ /vvdump/ ? 1 : 0,
            exit_when_done      => $options->{exit_when_done},
            slow_target         => 1,
            seeds_directory     => "$RESOURCES/seeds/libtpms",
            dictionary_file     => 0,
            binary_arguments    => "\@\@",
            sync_directory_name => $options->{sync_directory_name},
            parallel_fuzz_mode  => $options->{parallel_fuzz_mode},
            fuzzer_id           => $options->{fuzzer_id}
        }
    );

    my $pid = fork;
    return $pid if $pid;

    foreach my $ENV_VAR (keys(%{$ENV_VARS})) {
        $ENV{$ENV_VAR} = $ENV_VARS->{$ENV_VAR};
    }

    if ($options->{async} || $options->{sync_directory_name}) {
        # During parallel fuzzing we will monitor these instances on our own, so redirect STDOUT and STDERR to /dev/null
        # Do the same for async fuzzing
        open STDOUT, ">",  "/dev/null" or die "$0: open: $!";
        open STDERR, ">&", \*STDOUT    or exit 1;
    }

    # Need to run in shell using exec otherwise it runs it as sh -c $fuzz_command and the pid we get is of sh. So when
    # we try to kill it, it doesn't work.
    exec "exec $fuzz_command";
}

1;
