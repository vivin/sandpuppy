package libtins;

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

    my $libtins_base_dir = "$SUBJECTS/libtins";
    my $libtins_src_dir = "$libtins_base_dir/libtins-master";
    my $libtins_resources = "$RESOURCES/archives/libtins";

    $log->info("Checking if source is already unpacked...");
    if (! -d $libtins_src_dir) {
        $log->info("Source is not unpacked. Unpacking...");

        my $libtins_src = "$libtins_resources/libtins-master.tar.gz";
        if (! -f $libtins_src) {
            die "Could not find libtins source: $libtins_src";
        }

        if (! -d $libtins_base_dir) {
            system ("mkdir -p $libtins_base_dir 2> /dev/null") == 0
                or die "Failed to create $libtins_base_dir";
        }

        chdir $libtins_base_dir;
        system ("tar -zxvf $libtins_src");
    } else {
        $log->info("Source is already unpacked");
    }

    if (-e "$libtins_src_dir/build/Makefile") {
        $log->info("Previous build exists; cleaning.");
        system ("find $libtins_src_dir/build | xargs rm -rf");
    }

    system ("mkdir -p $libtins_src_dir/build");
    chdir "$libtins_src_dir/build";

    my $FUZZ_FACTORY = "$TOOLS/FuzzFactory";
    my $cc = "$FUZZ_FACTORY/afl-clang-fast";
    my $cxx = "$FUZZ_FACTORY/afl-clang-fast++";
    my $compiler_flags = "-fno-inline-functions -fno-discard-value-names -fno-unroll-loops";
    if ($options->{m32}) {
        $compiler_flags .= " -m32";
    }

    my $clang_waypoint_options = utils::build_options_string($options->{clang_waypoint_options});
    print ("cmake .. -DCMAKE_C_COMPILER=$cc -DCMAKE_CXX_COMPILER=$cxx -DCMAKE_CXX_FLAGS='$compiler_flags$clang_waypoint_options'\n");
    system ("cmake .. -DCMAKE_C_COMPILER=$cc -DCMAKE_CXX_COMPILER=$cxx -DCMAKE_CXX_FLAGS='$compiler_flags$clang_waypoint_options'");
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

    delete $ENV{"WAYPOINTS"};

    my $subject_directory = utils::get_subject_directory($experiment_name, $subject, $version);

    my $binary_base = "$subject_directory/binaries";
    my $binary_dir =  "$binary_base/$binary_context";
    my $binary_name = "readpcap";
    utils::create_binary_dir({
        binary_dir     => $binary_dir,
        artifact_names => [
            $binary_name,
            "libtins.so.4.4",
            "libtins.so"
        ],
        backup         => $options->{backup}
    });

    # Copy the shared libraries into the binary dir because the binary will need to use it. We can't just provide the
    # directory in the source to rpath because then all readpcap binaries will use the same shared libraries, which is
    # not what we want when we build and fuzz multiple targets. We also have to update libtins.so because it is a
    # symlink to libtins.so.4.4
    system ("cp $libtins_src_dir/build/lib/*.so* $binary_dir");

    $log->info("Building readpcap..");

    my $build_command = "$FUZZ_FACTORY/afl-clang-fast++ -std=c++11 -fno-inline-functions -fno-discard-value-names -fno-unroll-loops";

    # If the binary directory (which we get from the execution context) contains colons then we run into problems when
    # providing it to the linker so that it can find the libtins libraries that we put there. While no errors are shown
    # while linking, ldd will show that it cannot find the libtins so file. We could modify the execution context, but
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
    system ("$build_command $libtins_resources/readpcap.cpp -I$libtins_src_dir/include -L$safe_binary_dir -lpthread -ltins -Xlinker -rpath $safe_binary_dir -o $binary_dir/$binary_name\n");
    if ($? != 0) {
        delete $ENV{"AFL_USE_ASAN"};
        die "Building readpcap failed";
    }

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
            asan_memory_limit => 20971597,
            hang_timeout      => $waypoints =~ /vvdump/ ? "5000+" : 0,
            no_arithmetic     => $waypoints =~ /vvdump/ ? 1 : 0,
            no_splicing       => $waypoints =~ /vvdump/ ? 1 : 0,
            slow_target       => $waypoints =~ /vvdump/ ? 1 : 0,
            seeds_directory   => "$RESOURCES/seeds/libtins",
            binary_arguments  => "\@\@"
        })
    );
}

1;
