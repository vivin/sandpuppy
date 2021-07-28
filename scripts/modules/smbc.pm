package smbc;

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

    my $workspace = utils::get_workspace($experiment_name, $subject, $version);

    my $binary_base = "$workspace/binaries";
    my $binary_dir =  "$binary_base/$binary_context";
    my $binary_name = "smbc";
    utils::create_binary_dir({
        binary_dir     => $binary_dir,
        artifact_names => [$binary_name],
        backup         => $options->{backup}
    });

    my $smbc_src_dir = "$SUBJECTS/smbc";
    my $smbc_build_dir = "$smbc_src_dir/build";
    if (! -d $smbc_build_dir) {
        system ("mkdir $smbc_build_dir");
    }

    chdir $smbc_build_dir;
    system("ls -la");
    system ("rm -rf CMake* cmake_install.cmake codegen/ Makefile smbc");
    system("ls -la");

    my $FUZZ_FACTORY = "$TOOLS/FuzzFactory";
    my $cc = "$FUZZ_FACTORY/afl-clang-fast";
    my $cxx = "$FUZZ_FACTORY/afl-clang-fast++";
    my $compiler_flags = "-fno-inline-functions -fno-discard-value-names -fno-unroll-loops";
    if ($options->{m32}) {
        $compiler_flags .= " -m32";
    }

    my $clang_waypoint_options = utils::build_options_string($options->{clang_waypoint_options});
    print ("cmake .. -DCMAKE_C_COMPILER=$cc -DCMAKE_CXX_COMPILER=$cxx -DCMAKE_CXX_FLAGS='$compiler_flags$clang_waypoint_options -isystem /usr/include/SDL2'\n");
    system ("cmake .. -DCMAKE_C_COMPILER=$cc -DCMAKE_CXX_COMPILER=$cxx -DCMAKE_CXX_FLAGS='$compiler_flags$clang_waypoint_options -isystem /usr/include/SDL2'");
    if ($? != 0) {
       die "Generating Makefiles using CMake failed";
    }

    if ($binary_context =~ /-asan/) {
        $ENV{"AFL_USE_ASAN"} = 1;
    }

    if ($waypoints ne "none") {
        $ENV{"WAYPOINTS"} = $waypoints;
    }

    system ("make -j12");
    if ($? != 0) {
        delete $ENV{"WAYPOINTS"};
        delete $ENV{"AFL_USE_ASAN"};

        die "Make failed";
    }

    system ("mv smbc $binary_dir/$binary_name");

    delete $ENV{"WAYPOINTS"};
    delete $ENV{"AFL_USE_ASAN"};
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
            binary_arguments => "0",
            hang_timeout     => $waypoints =~ /vvdump/ ? "100000+" : 5000,
            slow_target      => $waypoints =~ /vvdump/,
            no_arithmetic    => $waypoints =~ /vvdump/,
            seeds_directory  => "$RESOURCES/seeds/smbc"
        })
    );
}

1;

#smartdsf-smbc--yoif-iks3-v2ro-wvcw-vvmax2
#smartdsf-smbc--u9nc-26vb-i7t9-dx5l-vvmax2
#smartdsf-smbc--pa9i-umb6-a9n8-kudz-vvmax2
#smartdsf-smbc--80hx-0w9i-gt71-xnid-vvmax2
#smartdsf-smbc--7zv5-fuvr-3koj-6sy6-vvmax2
#smartdsf-smbc--4cs6-29o3-3v8q-deic-vvmax2
