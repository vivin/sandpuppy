#/bin/bash

BASEPATH=~/Projects/phd
TOOLS=$BASEPATH/tools
RESOURCES=$BASEPATH/resources
BINARIES=$BASEPATH/binaries
RESULTS=$BASEPATH/results

FUZZ_FACTORY=$TOOLS/FuzzFactory

if [[ $# -lt 3 ]]; then
    echo "Syntax $0 <experiment-name> <libpng-version> <waypoints> [with_asan]"
    exit 1
fi

experiment_name=$1
version=$2
waypoints=$3
with_asan=$4
libpng_src_dir=$RESOURCES/libpng-$version

echo -n "Checking if source is already unpacked..."

if [ ! -d $libpng_src_dir ]; then
    echo "no"

    echo "Unpacking source."
    libpng_src=$RESOURCES/libpng-$version.tar.gz
    if [ ! -f $libpng_src ]; then
        echo "Could not find libpng source: $libpng_src"
        exit 1
    fi

    cd $RESOURCES
    tar -zxvf $libpng_src
    cd $libpng_src_dir

    echo "Patching source for no CRC check."
    patch < $RESOURCES/libpng-nocrc.patch

    cd $RESOURCES
else
    echo "yes"
fi


echo "Configuring, making, and instrumenting libpng $version with waypoints $waypoints for experiment $experiment_name..."

cd $libpng_src_dir

if [ -f "$libpng_src_dir/Makefile" ]; then
    echo "Makefile exists; cleaning."
    make clean
fi

if [ "$with_asan" == "with_asan" ]; then
    ASAN="-fsanitize=address"
fi

CLANG_OPTS="-fno-inline-functions -fno-discard-value-names -fno-unroll-loops"

if [ "$waypoints" != "none" ]; then
    # trace_directory is the directory where the instrumented binary will write traces to.
    trace_directory=$RESULTS/$experiment_name/libpng-$version/traces
    if [ ! -d $trace_directory ]; then
        mkdir -p $trace_directory
    fi

    export WAYPOINTS=$waypoints
    CC="$FUZZ_FACTORY/afl-clang-fast $ASAN $CLANG_OPTS -trace_directory=$RESULTS/$experiment_name/libpng-$version/traces -functions_file=$RESOURCES/functions_file.txt" ./configure --disable-shared && make -j4
else
    CC="$FUZZ_FACTORY/afl-clang-fast $ASAN $CLANG_OPTS" ./configure --disable-shared && make -j4
fi

if [ $? -ne 0 ]; then
    echo "Make failed :("
    unset WAYPOINTS

    exit 1
fi

libpng_lib_version=`echo $version | sed -e 's,\.[0-9]\+$,,' | sed -e 's,\.,,'`
libpng_lib_file=$libpng_src_dir/.libs/libpng$libpng_lib_version.a
if [ ! -f $libpng_lib_file ]; then
    echo "Could not find built libpng library at $libpng_lib_file";
    unset WAYPOINTS

    exit 1
fi

# Check if readpng exists (doesn't for 1.5.x and older) and if not, copy it over
if [ ! -f "$libpng_src_dir/contrib/libtests/readpng.c" ]; then
    cp $RESOURCES/readpng.c $libpng_src_dir/contrib/libtests
fi

echo "Building readpng..."
cd $libpng_src_dir/contrib/libtests

# We will not instrument readpng itself because we only care about the instrumented library (see if this actually works....)
readpng_binary_dir=$BINARIES/$experiment_name/libpng-$version
if [ ! -d $readpng_binary_dir ]; then
    mkdir -p $readpng_binary_dir
fi

# We used to be able to set trace_directory to /dev/null, but that's now causing a segfault. So we will just put it in /tmp
tmp_trace_dir="/tmp/traces/$experiment_name/libpng-$version"
if [ ! -d $tmp_trace_dir ]; then
    mkdir -p $tmp_trace_dir
fi

if [ "$waypoints" != "none" ]; then
    $FUZZ_FACTORY/afl-clang-fast $ASAN -trace_directory=$tmp_trace_dir -functions_file=$RESOURCES/empty_functions_file.txt ./readpng.c -lm -lz $libpng_lib_file -o $readpng_binary_dir/readpng
else
    $FUZZ_FACTORY/afl-clang-fast $ASAN ./readpng.c -lm -lz $libpng_lib_file -o $readpng_binary_dir/readpng
fi

if [ $? -ne 0 ]; then
    echo "Make failed :("
    unset WAYPOINTS

    exit 1
fi

unset WAYPOINTS
