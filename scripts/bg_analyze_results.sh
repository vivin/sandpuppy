#!/bin/bash

EXISTING_PID=$(ps -ux | grep -v grep | grep "result_analysis.pl $1 $2 $3 $4" | awk '{ print $2; }' | head -1)
if [[ -z "$EXISTING_PID" ]]; then
  nohup /home/vivin/Projects/phd/scripts/result_analysis.pl "$1" "$2" "$3" "$4" > /dev/null 2>&1 &
else
  echo "Script already running with pid $EXISTING_PID"
fi
