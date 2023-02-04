package pcapplusplus;

use strict;
use warnings FATAL => 'all';
use Log::Simple::Color;
use File::Path qw(make_path);
use utils;

my $log = Log::Simple::Color->new;
my $BASE_PATH = glob "~/Projects/phd";
my $TOOLS = "$BASE_PATH/tools";
my $RESOURCES = "$BASE_PATH/resources";
my $SUBJECTS = "$BASE_PATH/subjects";

sub build {
    my $experiment_name = $_[0];
    my $subject = $_[1];
    my $version = $_[2];
    my $waypoints = $_[3];
    my $binary_context = $_[4];
    my $options = $_[5];

    my $pcapplusplus_src_dir = "$SUBJECTS/pcapplusplus/PcapPlusPlus-master";
    my $pcapplusplus_build_dir = "$pcapplusplus_src_dir/Dist";
    my $pcapplusplus_resources = "$RESOURCES/archives/pcapplusplus";

    chdir $pcapplusplus_src_dir;
    system ("make clean");

    my $FUZZ_FACTORY = "$TOOLS/FuzzFactory";
    my $compiler_flags = "-fno-inline-functions -fno-discard-value-names -fno-unroll-loops";
    my $compiler = "$FUZZ_FACTORY/afl-clang-fast";

    my $clang_waypoint_options = utils::build_options_string($options->{clang_waypoint_options});
    if ($binary_context =~ /-asan/) {
        $ENV{"AFL_USE_ASAN"} = 1;
    }

    if ($waypoints ne "none") {
        $ENV{"WAYPOINTS"} = $waypoints;
    }

    $ENV{"CC"} = "$compiler $compiler_flags $clang_waypoint_options";
    $ENV{"CXX"} = "$compiler $compiler_flags $clang_waypoint_options";
    system ("./configure-linux.sh --default");

    #CC='$compiler' CXX='$compiler' CXXFLAGS='$compiler_flags $clang_waypoint_options'
    system ("make libs -j12");

    if ($? != 0) {
        delete $ENV{"WAYPOINTS"};
        delete $ENV{"AFL_USE_ASAN"};
        delete $ENV{"CC"};
        delete $ENV{"CXX"};

        die "Make failed";
    }

    delete $ENV{"CC"};
    delete $ENV{"CXX"};

    my $subject_directory = utils::get_subject_directory($experiment_name, $subject, $version);

    my $binary_base = "$subject_directory/binaries";
    my $binary_dir =  "$binary_base/$binary_context";
    my $binary_name = "readpcap";
    utils::create_binary_dir({
        binary_dir     => $binary_dir,
        artifact_names => [
            $binary_name,
            "libCommon++.a" ,
            "libPacket++.a",
            "libPcap++.a"
        ],
        backup         => $options->{backup}
    });

    system ("cp $pcapplusplus_build_dir/*.a $binary_dir");

    $log->info("Building readpcap...");

    # If the binary directory (which we get from the execution context) contains colons then we run into problems when
    # providing it to the linker so that it can find the pcap++ libraries that we put there. While no errors are shown
    # while linking, ldd will show that it cannot find the pcap++ so file. We could modify the execution context, but
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
    #system ("$build_command $libtpms_resources/readtpmc.c -I$libtpms_src_dir/include $libtpms_src_dir/src/.libs/libtpms.a $libtpms_src_dir/src/.libs/libtpms_tpm2.a $binary_dir/libb64.a -lcrypto -lssl -o $binary_dir/$binary_name");
    #print ("$FUZZ_FACTORY/afl-clang-fast++ $compiler_flags $clang_waypoint_options $pcapplusplus_resources/readpcap.cpp -I$pcapplusplus_build_dir/header -L$safe_binary_dir -static-libstdc++ -lPcap++ -lPacket++ -lCommon++ -lpcap -lpthread -rpath $safe_binary_dir -o $binary_dir/$binary_name");
    system ("$FUZZ_FACTORY/afl-clang-fast++ $compiler_flags $clang_waypoint_options $pcapplusplus_resources/readpcap.cpp -I$pcapplusplus_build_dir/header -L$safe_binary_dir -static-libstdc++ -lPcap++ -lPacket++ -lCommon++ -lpcap -lpthread -rpath $safe_binary_dir -o $binary_dir/$binary_name");
    if ($? != 0) {
        delete $ENV{"AFL_USE_ASAN"};
        delete $ENV{"WAYPOINTS"};
        die "Building readpcap failed";
    }

    delete $ENV{"AFL_USE_ASAN"};
    delete $ENV{"WAYPOINTS"};
}

sub get_fuzz_command {
    my $experiment_name = $_[0];
    my $subject = $_[1];
    my $version = $_[2];
    my $waypoints = $_[3];
    my $binary_context = $_[4];
    my $exec_context = $_[5];
    my $options = $_[6];

    utils::build_fuzz_command(
        $experiment_name,
        $subject,
        $version,
        $waypoints,
        $binary_context,
        $exec_context,
        utils::merge($options, {
            asan_memory_limit => 40971597,
            hang_timeout     => $waypoints =~ /vvdump/ ? "100000+" : 10000,
            slow_target      => $waypoints =~ /vvdump/ ? 1 : 0,
            seeds_directory  => "$RESOURCES/seeds/$subject",
            binary_arguments => "\@\@"
        })
    );
}

1;