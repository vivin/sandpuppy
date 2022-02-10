package cgc;

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

    my $subject_directory = utils::get_subject_directory($experiment_name, $subject, $version);

    my $binary_base = "$subject_directory/binaries";
    my $binary_dir =  "$binary_base/$binary_context";
    my $binary_name = $subject;
    utils::create_binary_dir({
        binary_dir     => $binary_dir,
        artifact_names => [$binary_name],
        backup         => $options->{backup}
    });

    my $cgc_src_dir = "$SUBJECTS/cb-multios";
    my $cgc_build_dir = "$cgc_src_dir/build";
    if (-d $cgc_build_dir) {
        system ("rm -rf $cgc_build_dir");
    }

    chdir $cgc_src_dir;

    my $FUZZ_FACTORY = "$TOOLS/FuzzFactory";
    my $cc = "$FUZZ_FACTORY/afl-clang-fast";
    my $cxx = "$FUZZ_FACTORY/afl-clang-fast++";
    my $compiler_flags = "-fno-inline-functions -fno-discard-value-names -fno-unroll-loops -m32";

    my $clang_waypoint_options = utils::build_options_string($options->{clang_waypoint_options});
    if ($binary_context =~ /-asan/) {
        $ENV{"AFL_USE_ASAN"} = 1;
    }

    if ($waypoints ne "none") {
        $ENV{"WAYPOINTS"} = $waypoints;
    }

    # We are always going to build 32-bit, so we will never use build64.sh
    print ("env CMAKE_C_COMPILER=\"$cc\" CMAKE_CXX_COMPILER=\"$cxx\" CMAKE_ASM_COMPILER=\"$cc\" CMAKE_CXX_FLAGS='$compiler_flags$clang_waypoint_options' CMAKE_C_FLAGS='$compiler_flags$clang_waypoint_options' CMAKE_ASM_FLAGS='$compiler_flags$clang_waypoint_options' ./build.sh $subject");
    system ("env CMAKE_C_COMPILER=\"$cc\" CMAKE_CXX_COMPILER=\"$cxx\" CMAKE_ASM_COMPILER=\"$cc\" CMAKE_CXX_FLAGS='$compiler_flags$clang_waypoint_options' CMAKE_C_FLAGS='$compiler_flags$clang_waypoint_options' CMAKE_ASM_FLAGS='$compiler_flags$clang_waypoint_options' ./build.sh $subject");
    if ($? != 0) {
        delete $ENV{"WAYPOINTS"};
        delete $ENV{"AFL_USE_ASAN"};

        die "Make failed";
    }

    system ("mv $cgc_build_dir/challenges/$subject/$binary_name $binary_dir/$binary_name");

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
            hang_timeout     => $waypoints =~ /vvdump/ ? "100000+" : 5000,
            slow_target      => $waypoints =~ /vvdump/,
            seeds_directory  => "$RESOURCES/seeds/hawaii_sets"
        })
    );
}

1;
