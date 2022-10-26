#!/bin/bash

EXISTING_PID=$(ps -u | grep -v grep | grep "analyze_results.pl $1 $2 $3 $4" | awk '{ print \$2; }')
if [[ -z "$EXISTING_PID" ]]; then
  /home/vivin/Projects/phd/scripts/analyze_results.pl "$1" "$2" "$3" "$4" > /dev/null 2>&1 &
fi
