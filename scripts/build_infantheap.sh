#/bin/bash

BASEPATH=~/Projects/phd
TOOLS=$BASEPATH/tools
RESOURCES=$BASEPATH/resources
BINARIES=$BASEPATH/binaries
RESULTS=$BASEPATH/results

FUZZ_FACTORY=$TOOLS/FuzzFactory

if [[ $# -lt 2 ]]; then
    echo "Syntax: $0 <experiment-name> <waypoints> [with_asan]"
    exit 1
fi

experiment_name=$1
waypoints=$2
with_asan=$3
infantheap_src_dir=$FUZZ_FACTORY/infantheap

infantheap_binary_dir=$BINARIES/$experiment_name/infantheap
if [ ! -d $infantheap_binary_dir ]; then
    mkdir -p $infantheap_binary_dir
fi

if [ "$with_asan" == "with_asan" ]; then
    ASAN="-fsanitize=address"
fi

if [ "$waypoints" != "none" ]; then
    # trace_directory is the directory where the instrumented binary will write traces to.
    trace_directory=$RESULTS/$experiment_name/infantheap/traces
    if [ ! -d $trace_directory ]; then
        mkdir -p $trace_directory
    fi

    export WAYPOINTS=$waypoints
    $FUZZ_FACTORY/afl-clang-fast $ASAN -fno-inline-functions -fno-discard-value-names -trace_directory=$trace_directory -functions_file=$RESOURCES/functions_file.txt $infantheap_src_dir/infantheap.c -o $infantheap_binary_dir/infantheap
else
    $FUZZ_FACTORY/afl-clang-fast $ASAN $infantheap_src_dir/infantheap.c -o $infantheap_binary_dir/infantheap
fi

if [ $? -ne 0 ]; then
    echo "Compilation failed :("
    unset WAYPOINTS

    exit 1
fi

unset WAYPOINTS

