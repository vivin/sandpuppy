#/bin/bash

BASEPATH=~/Projects/phd
TOOLS=$BASEPATH/tools
RESOURCES=$BASEPATH/resources
BINARIES=$BASEPATH/binaries
RESULTS=$BASEPATH/results

FUZZ_FACTORY=$TOOLS/FuzzFactory

if [[ $# -lt 3 ]]; then
    echo "Syntax $0 <experiment-name> <readelf-version> <waypoints> [with_asan]"
    exit 1
fi

experiment_name=$1
version=$2
waypoints=$3
with_asan=$4
binutils_src_dir=$RESOURCES/binutils-$version

with_trace=0
if [[ "$waypoints" == *"trace"* ]]; then
    with_trace=1
fi

echo -n "Checking if source is already unpacked..."

if [ ! -d $binutils_src_dir ]; then
    echo "no"

    echo "Unpacking source."
    binutils_src=$RESOURCES/binutils-$version.tar.bz2
    if [ ! -f $binutils_src ]; then
        echo "Could not find binutils source: $binutils_src"
        exit 1
    fi

    cd $RESOURCES
    tar -jxvf $binutils_src
else
    echo "yes"
fi


echo "Configuring, making, and instrumenting readelf $version with waypoints $waypoints for experiment $experiment_name..."

cd $binutils_src_dir

if [ -f "$binutils_src_dir/Makefile" ]; then
    echo "Makefile exists; cleaning."
    make clean
    find . -type f -name "Makefile" | grep -v zlib | xargs rm # get rid of all Makefiles except those in zlib
fi

if [ "$with_asan" == "with_asan" ]; then
    ASAN="-fsanitize=address"
fi

if [ "$waypoints" != "none" ]; then
    # trace_directory is the directory where the instrumented binary will write traces to.
    trace_directory=$RESULTS/$experiment_name/readelf-$version/traces
    if [ $with_trace -eq 1 ] && [ ! -d $trace_directory ]; then
        mkdir -p $trace_directory
    fi

    export WAYPOINTS=$waypoints

    if [ $with_trace -eq 1 ]; then
        TRACE_OPTION="-trace_directory=$RESULTS/$experiment_name/readelf-$version/traces"
    fi

    CC="$FUZZ_FACTORY/afl-clang-fast $ASAN $TRACE_OPTION -functions_file=$RESOURCES/functions_file.txt" ./configure && make -j4
else
    CC="$FUZZ_FACTORY/afl-clang-fast $ASAN" ./configure && make -j4
fi

if [ $? -ne 0 ]; then
    echo "Make failed :("
    unset WAYPOINTS

    exit 1
fi

# Check if readelf exists
readelf_binary=$binutils_src_dir/binutils/readelf
if [ ! -e $readelf_binary ]; then
    echo "Could not find readelf binary :("
    unset WAYPOINTS

    exit 1
fi

# We will not instrument readpng itself because we only care about the instrumented library (see if this actually works....)
readelf_binary_dir=$BINARIES/$experiment_name/readelf-$version
if [ ! -d $readelf_binary_dir ]; then
    mkdir -p $readelf_binary_dir
fi

# Copy readelf binary over to binaries directory
cp $readelf_binary $readelf_binary_dir

unset WAYPOINTS
