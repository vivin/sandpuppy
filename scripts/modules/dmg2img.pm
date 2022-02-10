package dmg2img;

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
    my $binary_name = "dmg2img";
    utils::create_binary_dir({
        binary_dir     => $binary_dir,
        artifact_names => [$binary_name],
        backup         => $options->{backup}
    });

    my $dmg2img_base_dir = "$SUBJECTS/dmg2img";
    my $dmg2img_src_dir = "$dmg2img_base_dir/dmg2img-develop";
    my $dmg2img_resources = "$RESOURCES/archives/dmg2img";

    $log->info("Checking if source is already unpacked...");
    if (! -d $dmg2img_src_dir) {
        $log->info("Source is not unpacked. Unpacking...");

        my $dmg2img_src = "$dmg2img_resources/dmg2img-develop.zip";
        if (! -f $dmg2img_src) {
            die "Could not find dmg2img source: $dmg2img_src";
        }

        if (! -d $dmg2img_base_dir) {
            system ("mkdir -p $dmg2img_base_dir 2> /dev/null") == 0
                or die "Failed to create $dmg2img_base_dir";
        }

        chdir $dmg2img_base_dir;
        system ("unzip $dmg2img_src");
    } else {
        $log->info("Source is already unpacked");
    }

    chdir $dmg2img_src_dir;

    if (-f "$dmg2img_src_dir/Makefile") {
        $log->info("Makefile exists; cleaning.");
        system ("make clean");
    }

    my $FUZZ_FACTORY = "$TOOLS/FuzzFactory";
    my $build_command = "$FUZZ_FACTORY/afl-clang-fast -fno-inline-functions -fno-discard-value-names -fno-unroll-loops";
    if ($options->{m32}) {
        $build_command .= " -m32";
    }

    if ($binary_context =~ /-asan/) {
        $ENV{"AFL_USE_ASAN"} = 1;
    }

    if ($waypoints ne "none") {
        $ENV{"WAYPOINTS"} = $waypoints;
    }

    my $clang_waypoint_options = utils::build_options_string($options->{clang_waypoint_options});
    system ("make CC='$build_command$clang_waypoint_options' -j12");
    if ($? != 0) {
        delete $ENV{"WAYPOINTS"};
        delete $ENV{"AFL_USE_ASAN"};

        die "Make failed";
    }

    delete $ENV{"WAYPOINTS"};

    system ("mv dmg2img $binary_dir/$binary_name");

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
            # preload           => $binary_context =~ /-asan/ ? utils::get_clang_asan_dso() : 0,
            #asan_memory_limit => 40971597,
            hang_timeout      => $waypoints =~ /vvdump/ ? "5000+" : 0,
            no_arithmetic     => $waypoints =~ /vvdump/ ? 1 : 0,
            no_splicing       => $waypoints =~ /vvdump/ ? 1 : 0,
            slow_target       => $waypoints =~ /vvdump/ ? 1 : 0,
            seeds_directory   => "$RESOURCES/seeds/dmg2img",
            binary_arguments  => "\@\@"
        })
    );
}

1;
