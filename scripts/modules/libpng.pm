package libpng;

use strict;
use warnings;
use Log::Simple::Color;
use File::Path qw(make_path);

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
    my $context = $_[3];
    my $waypoints = $_[4];

    my $libpng_src_dir = "$SUBJECTS/libpng/$version";
    my $libpng_resources = "$RESOURCES/tarballs/libpng";

    $log->info("Checking if source is already unpacked...");
    if (! -d $libpng_src_dir) {
        $log->info("Source is not unpacked. Unpacking...");

        my $libpng_src = "$libpng_resources/libpng-$version.tar.gz";
        if (! -f $libpng_src) {
            die "Could not find libpng source: $libpng_src";
        }

        chdir "$SUBJECTS/libpng";
        system ("tar -zxvf $libpng_src");
        rename "libpng-$version", $version;

        chdir $libpng_src_dir;
        system ("patch < $libpng_resources/libpng-nocrc.patch");

    } else {
        $log->info("Source is already unpacked");
    }

    chdir $libpng_src_dir;

    if (-f "$libpng_src_dir/Makefile") {
        $log->info("Makefile exists; cleaning.");
        system ("make clean");
    }

    my $FUZZ_FACTORY = "$TOOLS/FuzzFactory";
    my $build_command = "$FUZZ_FACTORY/afl-clang-fast -fno-inline-functions -fno-discard-value-names -fno-unroll-loops";

    my $use_asan = ($context =~ /asan/);
    if ($use_asan) {
        $build_command .= " -fsanitize=address";
    }

    # TODO: have to account for WEJON instrumentation waypoint eventually... similar arg like functions file

    if ($waypoints ne "none") {
        $ENV{"WAYPOINTS"} = $waypoints;
        system ("CC=\"$build_command\" ./configure --disable-shared && make -j4");
        delete $ENV{"WAYPOINTS"};
    } else {
        system $build_command;
    }

    if ($? != 0) {
        die "Make failed";
    }

    my $workspace = "$BASEWORKSPACEPATH/$experiment_name/$subject-$version";

    my $binary_base = "$workspace/binaries";
    my $binary_dir =  "$binary_base/$context";
    my $binary = "$binary_dir/readpng";

    if (-d $binary_dir and -e $binary) {
        my $result = `find $binary_dir -type f -name "*backup[0-9]" | sed -e 's,^.*backup,,' | sort -nr | head -1`;
        if ($result eq "") {
            $result = -1;
        }

        my $new_version = ++$result;

        $log->info("Backing up existing binary to backup version $new_version");
        system ("cp $binary $binary_dir/readpng.backup$new_version");
    } elsif (! -d $binary_dir) {
        make_path($binary_dir);
    }

    my $libpng_lib_version = $version;
    $libpng_lib_version =~ s/\.[0-9]$//;
    $libpng_lib_version =~ s/\.//;

    my $libpng_lib_file = "$libpng_src_dir/.libs/libpng$libpng_lib_version.a";
    if (! -f $libpng_lib_file) {
        die "Could not find build libpng library at $libpng_lib_file";
    }

    if (! -f "$libpng_src_dir/contrib/libtests/readpng.c") {
        system ("cp $libpng_resources/readpng.c $libpng_src_dir/contrib/libtests");
    }

    chdir "$libpng_src_dir/contrib/libtests";

    $log->info("Building readpng..");

    system ("$build_command ./readpng.c -lm -lz $libpng_lib_file -o $binary");
    if ($? != 0) {
        die "Building readpng failed";
    }
}

sub fuzz {
    my $pid = fork;
    return $pid if $pid;

    my $experiment_name = $_[0];
    my $subject = $_[1];
    my $version = $_[2];
    my $exec_context = $_[3];
    my $waypoints = $_[4];
    my $binary_context = $_[5];
    my $resume = $_[6];

    my $workspace = "$BASEWORKSPACEPATH/$experiment_name/$subject-$version";
    my $results_base = "$workspace/results";
    my $results_dir = "$results_base/$exec_context";

    if (!$resume) {
        if (-d $results_dir) {
            my $result = `find $results_base -type d -regex '.*$exec_context.backup[0-9]+' | sed -e 's,^.*backup,,' | sort -nr | head -1`;
            if ($result eq "") {
                $result = -1;
            }

            my $new_version = ++$result;

            $log->info("Backing up existing results directory to backup version $new_version");
            system ("mv $results_dir $results_base/$exec_context.backup$new_version");
        }

        make_path($results_dir);
    } elsif (! -d $results_dir) {
        die "Cannot resume because cannot find results dir at $results_dir";
    }

    my $binary = "$workspace/binaries/$binary_context/readpng";
    if (! -e $binary) {
        die "Could not find binary for binary context $binary_context at $binary";
    }

    my $FUZZ_FACTORY = "$TOOLS/FuzzFactory";
    my $fuzz_command = "$FUZZ_FACTORY/afl-fuzz";
    if ($waypoints ne "none") {
        $fuzz_command .= " -p";
    }

    if ($resume) {
        $fuzz_command .= " -i-"
    } else {
        my $seeds_directory = "$RESOURCES/seeds/libpng/images";
        my $dictionary_directory = "$RESOURCES/seeds/libpng/dictionary";
        $fuzz_command .= " -i $seeds_directory -x $dictionary_directory/png.dict";
    }

    $fuzz_command .= " -o $results_dir -T \"$subject-$version-$experiment_name-$exec_context\"";

    my $use_asan = ($binary_context =~ /asan/);
    if ($use_asan) {
        $ENV{"ASAN_OPTIONS"} = "abort_on_error=1:detect_leaks=0:symbolize=0:exitcode=86";
        $fuzz_command .= " -m none";
    }

    if ($waypoints =~ /vvdump/) {
        $fuzz_command .= " -t 300";
    }

    $fuzz_command .= " $binary";

    # Need to run in shell using exec otherwise it runs it as sh -c $fuzz_command and the pid we get is of sh. So when
    # we try to kill it, it doesn't work.
    exec "exec $fuzz_command";
}

1;