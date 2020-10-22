#/bin/bash

BASEPATH=~/Projects/phd
SCRIPTS=$BASEPATH/scripts
TOOLS=$BASEPATH/tools
RESOURCES=$BASEPATH/resources
BINARIES=$BASEPATH/binaries
RESULTS=$BASEPATH/results

FUZZ_FACTORY=$TOOLS/FuzzFactory

if [[ $# -lt 3 ]]; then
    echo "Syntax: $0 <experiment-name> <libpng-version> <waypoints> [save_all] [with_asan]"
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

echo -n "Checking if readpng binary exists..."

readpng_binary_dir=$BINARIES/$experiment_name/libpng-$version

if [ ! -f "$readpng_binary_dir/readpng" ]; then
    echo "no"

    $SCRIPTS/build_libpng.sh $experiment_name $version $waypoints $with_asan
    if [ $? -ne 0 ]; then
        echo "Build failed :("
        exit 1
    fi
else
    echo "yes"
fi

experiment_results_directory=$RESULTS/$experiment_name/libpng-$version

if [ "$waypoints" != "none" ]; then
    trace_directory=$experiment_results_directory/traces
    if [ ! -d $trace_directory ]; then
        mkdir -p $trace_directory
    fi
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
    export ASAN_OPTIONS="abort_on_error=1:symbolize=0:suppress_equal_pcs=0:exitcode=86:print_summary=0:coverage_pcs=0:symbolize_inline_frames=0:print_legend=0:print_full_thread_history=0"
    MEM_LIMIT_OPTION="-m none"
    using_asan="yes"
fi

start_time=`date`
echo "Experiment: $experiment_name" > $fuzz_output_directory/info.txt
echo "Waypoints: $waypoints" >> $fuzz_output_directory/info.txt
echo "ASAN: $using_asan" >> $fuzz_output_directory/info.txt
echo "Start time: $start_time" >> $fuzz_output_directory/info.txt

if [ "$waypoints" != "none" ]; then
    $FUZZ_FACTORY/afl-fuzz $SAVE_ALL_FLAG -p -i $FUZZ_FACTORY/testcases/images/png/ -o $fuzz_output_directory -x $FUZZ_FACTORY/dictionaries/png.dict -T "libpng-$version-$experiment_name" -R $trace_directory $MEM_LIMIT_OPTION $readpng_binary_dir/readpng
else
    $FUZZ_FACTORY/afl-fuzz $SAVE_ALL_FLAG -i $FUZZ_FACTORY/testcases/images/png/ -o $fuzz_output_directory -x $FUZZ_FACTORY/dictionaries/png.dict -T "libpng-$version-$experiment_name" $MEM_LIMIT_OPTION $readpng_binary_dir/readpng
fi
