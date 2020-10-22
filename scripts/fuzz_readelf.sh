#/bin/bash

BASEPATH=~/Projects/phd
SCRIPTS=$BASEPATH/scripts
TOOLS=$BASEPATH/tools
RESOURCES=$BASEPATH/resources
BINARIES=$BASEPATH/binaries
RESULTS=$BASEPATH/results

FUZZ_FACTORY=$TOOLS/FuzzFactory

if [[ $# -lt 3 ]]; then
    echo "Syntax: $0 <experiment-name> <readelf-version> <waypoints> [save_all] [with_asan]"
    exit 1
fi

experiment_name=$1
version=$2
waypoints=$3
save_all=$4
with_asan=$5

if [[ $# -eq 4 ]]; then
    if [ "$save_all" == "with_asan" ]; then
        with_asan=$save_all
        save_all=""
    fi
fi

with_trace=0
if [[ "$waypoints" == *"trace"* ]]; then
    with_trace=1
fi

echo -n "Checking if readelf binary exists..."

readelf_binary_dir=$BINARIES/$experiment_name/readelf-$version

if [ ! -f "$readelf_binary_dir/readelf" ]; then
    echo "no"

    $SCRIPTS/build_readelf.sh $experiment_name $version $waypoints $with_asan
    if [ $? -ne 0 ]; then
        echo "Build failed :("
        exit 1
    fi
else
    echo "yes"
fi

experiment_results_directory=$RESULTS/$experiment_name/readelf-$version

if [ $with_trace -eq 1 ] && [ "$waypoints" != "none" ]; then
    trace_directory=$experiment_results_directory/traces
    if [ ! -d $trace_directory ]; then
        mkdir -p $trace_directory
    fi

    TRACE_DIRECTORY_OPTION="-R $trace_directory"
fi

fuzz_output_directory=$experiment_results_directory/fuzz
if [ ! -d $fuzz_output_directory ]; then
    mkdir -p $fuzz_output_directory
fi

echo "Starting fuzzer..."

if [ "$save_all" == "save_all" ]; then
  SAVE_ALL_FLAG="-e"
fi

using_asan="no"
if [ "$with_asan" == "with_asan" ]; then
    export ASAN_OPTIONS="abort_on_error=1:symbolize=0:exitcode=86"
    MEM_LIMIT_OPTION="-m none"
    using_asan="yes"
fi

start_time=`date`
echo "Experiment: $experiment_name" > $fuzz_output_directory/info.txt
echo "Waypoints: $waypoints" >> $fuzz_output_directory/info.txt
echo "ASAN: $using_asan" >> $fuzz_output_directory/info.txt
echo "Start time: $start_time" >> $fuzz_output_directory/info.txt

# NOTE: the @@ at the end means that we are passing in the elf file as a command line argument and it is the second argument. The first argument is the switch -a which means display all information from elf file
if [ "$waypoints" != "none" ]; then
    $FUZZ_FACTORY/afl-fuzz $SAVE_ALL_FLAG -p -i $RESOURCES/readelf-seeds -o $fuzz_output_directory -T "readelf-$version-$experiment_name" $TRACE_DIRECTORY_OPTION $MEM_LIMIT_OPTION $readelf_binary_dir/readelf -a @@
else
    $FUZZ_FACTORY/afl-fuzz $SAVE_ALL_FLAG -i $RESOURCES/readelf-seeds -o $fuzz_output_directory -T "readelf-$version-$experiment_name" $MEM_LIMIT_OPTION $readelf_binary_dir/readelf -a @@
fi
