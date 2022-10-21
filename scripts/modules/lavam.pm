package lavam;

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

    my $lavam_src_dir = "$SUBJECTS/LAVA-M/$subject/coreutils-8.24-lava-safe";
    my $lavam_build_dir = "$lavam_src_dir/src";

    chdir $lavam_src_dir;
    system ("make clean");

    my $FUZZ_FACTORY = "$TOOLS/FuzzFactory";
    my $build_command = "$FUZZ_FACTORY/afl-clang-fast -fno-inline-functions -fno-discard-value-names -fno-unroll-loops -m32";

    my $clang_waypoint_options = utils::build_options_string($options->{clang_waypoint_options});
    if ($binary_context =~ /-asan/) {
        $ENV{"AFL_USE_ASAN"} = 1;
    }

    if ($waypoints ne "none") {
        $ENV{"WAYPOINTS"} = $waypoints;
    }

    system ("CC='$build_command$clang_waypoint_options' ./configure  LIBS=\"-lacl\" && make -j12");
    if ($? != 0) {
        delete $ENV{"WAYPOINTS"};
        delete $ENV{"AFL_USE_ASAN"};

        die "Make failed";
    }

    system ("mv $lavam_build_dir/$binary_name $binary_dir/$binary_name");

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

    my $binary_opts = {
        base64 => "-d",
        md5sum => "-c",
        who    => "",
        uniq   => ""
    };

    my $binary_option = $binary_opts->{$subject};
    utils::build_fuzz_command(
        $experiment_name,
        $subject,
        $version,
        $waypoints,
        $binary_context,
        $exec_context,
        utils::merge($options, {
            hang_timeout     => $waypoints =~ /vvdump/ ? "100000+" : 5000,
            slow_target      => $waypoints =~ /vvdump/ ? 1 : 0,
            seeds_directory  => "$RESOURCES/seeds/$subject",
            binary_arguments => "$binary_option \@\@"
        })
    );
}

1;