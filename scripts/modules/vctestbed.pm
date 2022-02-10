package vctestbed;

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
    my $binary_dir = "$binary_base/$binary_context";
    my $binary_name = "vctestbed";
    utils::create_binary_dir({
        binary_dir     => $binary_dir,
        artifact_names => [$binary_name],
        backup         => $options->{backup}
    });

    my $FUZZ_FACTORY = "$TOOLS/FuzzFactory";
    my $build_command = "$FUZZ_FACTORY/afl-clang-fast -fno-inline-functions -fno-discard-value-names -fno-unroll-loops"
        . ($options->{m32} ? " -m32" : "")
        . utils::build_options_string($options->{clang_waypoint_options})
        . " vctestbed.c -o $binary_dir/$binary_name";

    if ($binary_context =~ /-asan/) {
        $ENV{"AFL_USE_ASAN"} = 1;
    }

    if ($waypoints ne "none") {
        $ENV{"WAYPOINTS"} = $waypoints;
    }

    my $src_dir = "$SUBJECTS/vctestbed";
    chdir $src_dir;

    system $build_command;
    if ($? != 0) {
        delete $ENV{"WAYPOINTS"};
        delete $ENV{"AFL_USE_ASAN"};

        die "Build failed";
    }

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

    return utils::build_fuzz_command(
        $experiment_name,
        $subject,
        $version,
        $waypoints,
        $binary_context,
        $exec_context,
        utils::merge($options, {
            no_splicing       => $waypoints =~ /vvdump/ ? 1 : 0,
            seeds_directory   => "$RESOURCES/seeds/vctestbed"
        })
    );
}

1;