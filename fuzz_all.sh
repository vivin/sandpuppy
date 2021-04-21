#!/bin/bash

if [ "$#" -ne 4 ]; then
    echo "$0 <experiment> <waypoints> <binary-context> <execution-context>"
fi

experiment=$1
waypoints=$2
binary_context=$3
execution_context=$4

scripts/exp.pl ${experiment} fuzz libtpms with waypoints ${waypoints} using ${binary_context} as ${execution_context}
scripts/exp.pl ${experiment} fuzz maze with waypoints ${waypoints} using ${binary_context} as ${execution_context}
scripts/exp.pl ${experiment} fuzz rarebug with waypoints ${waypoints} using ${binary_context} as ${execution_context}
scripts/exp.pl ${experiment} fuzz infantheap with waypoints ${waypoints} using ${binary_context} as ${execution_context}
scripts/exp.pl ${experiment} fuzz libpng:1.5.9 with waypoints ${waypoints} using ${binary_context} as ${execution_context}
scripts/exp.pl ${experiment} fuzz readelf:2.32 with waypoints ${waypoints} using ${binary_context} as ${execution_context}

