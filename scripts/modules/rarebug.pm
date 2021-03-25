package rarebug;

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

    my $workspace = "$BASEWORKSPACEPATH/$experiment_name/$subject";

    my $binary_base = "$workspace/binaries";
    my $binary_dir =  "$binary_base/$binary_context";
    my $binary_name = "rarebug";
    utils::create_binary_dir_and_backup_existing($binary_dir, $binary_name);

    my $FUZZ_FACTORY = "$TOOLS/FuzzFactory";
    my $build_command = "$FUZZ_FACTORY/afl-clang-fast -fno-inline-functions -fno-discard-value-names -fno-unroll-loops";
    if ($additional_clang_args) {
        $build_command .= " $additional_clang_args";
    }

    my $use_asan = ($binary_context =~ /asan/);
    if ($use_asan) {
        $ENV{"AFL_USE_ASAN"} = 1;
    }

    my $use_vvperm = ($waypoints =~ /vvperm/);
    if ($use_vvperm) {
        $build_command .= " -variables_file=$RESOURCES/rarebug_vvperm_variables_file.txt"
    }

    my $src_dir = "$SUBJECTS/rarebug";

    $build_command .= " $src_dir/rarebug.c -o $binary_dir/$binary_name";

    if ($waypoints ne "none") {
        $ENV{"WAYPOINTS"} = $waypoints;
        system $build_command;
    } else {
        system $build_command;
    }

    if ($? != 0) {
        die "Build failed";
    }

    delete $ENV{"WAYPOINTS"};
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
            binary_name          => "rarebug",
            resume               => $options->{resume},
            use_asan             => $binary_context =~ /asan/ ? 1 : 0,
            hang_timeout         => $waypoints =~ /vvdump/ ? 100 : 0,
            non_deterministic    => 0,
            seeds_directory      => "$RESOURCES/seeds/rarebug",
            dictionary_file      => 0,
            binary_arguments     => 0,
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