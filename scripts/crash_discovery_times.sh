#/bin/bash

function prettytime {
    local time=$1
    local days=$((time/60/60/24))
    local hours=$((time/60/60%24))
    local minutes=$((time/60%60))
    local seconds=$((time%60))
    (( $days > 0 )) && echo -n "$days days "
    (( $hours > 0 )) && echo -n "$hours hours "
    (( $minutes > 0 )) && echo -n "$minutes minutes "
    (( $days > 0 || $hours > 0 || $minutes > 0 )) && echo -n "and "
    echo -n "$seconds seconds"
}

if [[ $# -lt 1 ]]; then
    echo "Syntax: $0 <fuzz-results-dir>"
    exit 1
fi

fuzz_results_dir=$1
info_file=$fuzz_results_dir/info.txt

if [ ! -f $info_file ]; then
    echo "Could not find info file: $info_file"
    exit 1
fi

start_epoch_time=`cat $info_file | grep "Start time" | sed -e 's,^.*: ,,' | xargs -I{} date -d '{}' +"%s"`

# Get all trace files sorted in ascending order
for file in $(find $fuzz_results_dir/crashes -name id\* | grep -v "\.trace" | xargs -I{} sh -c 't=`stat -c "%Y" {}`; echo "{} $t"' | sort -nk1 | sed -e 's, .*$,,'); do
    last_modified_time=`stat -c '%Y' $file`
    difference=`expr $last_modified_time - $start_epoch_time`
    formatted=$(prettytime $difference)
    echo "$file created at +$formatted ($difference seconds)"
done   
