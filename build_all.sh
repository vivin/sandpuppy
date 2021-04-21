#!/bin/bash

if [ "$#" -ne 3 ]; then
    echo "$0 <experiment> <waypoints> <binary-context>"
fi

experiment=$1
waypoints=$2
binary_context=$3

scripts/exp.pl ${experiment} build maze with waypoints ${waypoints} as ${binary_context}
scripts/exp.pl ${experiment} build rarebug with waypoints ${waypoints} as ${binary_context}
scripts/exp.pl ${experiment} build infantheap with waypoints ${waypoints} as ${binary_context}
scripts/exp.pl ${experiment} build libtpms with waypoints ${waypoints} as ${binary_context}
scripts/exp.pl ${experiment} build libpng:1.5.9 with waypoints ${waypoints} as ${binary_context}
scripts/exp.pl ${experiment} build readelf:2.32 with waypoints ${waypoints} as ${binary_context}

