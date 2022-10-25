package jsoncpp;

use strict;
use warnings FATAL => 'all';
use Log::Simple::Color;
use File::Path qw(make_path);
use YAML::XS;
use Cpanel::JSON::XS;
use utils;

my $log = Log::Simple::Color->new;
my $codec = Cpanel::JSON::XS->new->ascii->pretty->allow_nonref;

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
    my $binary_name = "readjson";
    utils::create_binary_dir({
        binary_dir     => $binary_dir,
        artifact_names => [$binary_name],
        backup         => $options->{backup}
    });

    my $jsoncpp_src_dir = "$SUBJECTS/jsoncpp";
    my $jsoncpp_resources = "$RESOURCES/archives/jsoncpp";
    my $jsoncpp_build_dir = "$jsoncpp_src_dir/build";
    if (! -d $jsoncpp_build_dir) {
        system ("mkdir $jsoncpp_build_dir");
    }

    chdir $jsoncpp_build_dir;
    system("ls -la");
    system ("rm -rf CMake* *.cmake *.tcl *.txt version Makefile bin include lib pkg-config src Testing");
    system("ls -la");

    my $FUZZ_FACTORY = "$TOOLS/FuzzFactory";
    my $cc = "$FUZZ_FACTORY/afl-clang-fast";
    my $cxx = "$FUZZ_FACTORY/afl-clang-fast++";
    my $compiler_flags = "-fno-inline-functions -fno-discard-value-names -fno-unroll-loops";
    if ($options->{m32}) {
        $compiler_flags .= " -m32";
    }

    my $clang_waypoint_options = utils::build_options_string($options->{clang_waypoint_options});
    print ("cmake .. -DCMAKE_C_COMPILER=$cc -DCMAKE_CXX_COMPILER=$cxx -DCMAKE_CXX_FLAGS='$compiler_flags$clang_waypoint_options' -DCMAKE_BUILD_TYPE=release -DBUILD_STATIC_LIBS=ON -DBUILD_SHARED_LIBS=OFF -DARCHIVE_INSTALL_DIR=. -G \"Unix Makefiles\"\n");
    system ("cmake .. -DCMAKE_C_COMPILER=$cc -DCMAKE_CXX_COMPILER=$cxx -DCMAKE_CXX_FLAGS='$compiler_flags$clang_waypoint_options' -DCMAKE_BUILD_TYPE=release -DBUILD_STATIC_LIBS=ON -DBUILD_SHARED_LIBS=OFF -DARCHIVE_INSTALL_DIR=. -G \"Unix Makefiles\"");
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

    $log->info("Building readjson...");

    my $build_command = "$FUZZ_FACTORY/afl-clang-fast++ -fno-inline-functions -fno-discard-value-names -fno-unroll-loops";
    print ("$build_command $jsoncpp_resources/readjson.cpp -I../include lib/libjsoncpp.a -o $binary_dir/$binary_name\n");
    system ("$build_command $jsoncpp_resources/readjson.cpp -I../include lib/libjsoncpp.a -o $binary_dir/$binary_name");

    if ($? != 0) {
        delete $ENV{"AFL_USE_ASAN"};
        delete $ENV{"WAYPOINTS"};
        die "Building readjson failed";
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
            hang_timeout     => $waypoints =~ /vvdump/ ? "100000+" : 5000,
            slow_target      => $waypoints =~ /vvdump/ ? 1 : 0,
            seeds_directory  => "$RESOURCES/seeds/$subject",
            binary_arguments => "\@\@"
        })
    );
}

sub check_input_is_valid_json {
    my $input_file = $_[0];

    open my $fh, "<", $input_file or die "Cannot open file $input_file";
    my $contents = do {local $/; <$fh>};
    close $fh;

    my $valid = 1;
    my $data = eval { $codec->decode($contents) };
    if ($@) {
        $valid = 0;
    }

    #print "\n $input_file is valid json: $valid\n";

    return $valid;
}

1;
