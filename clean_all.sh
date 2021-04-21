#!/bin/bash

if [ "$#" -ne 4 ]; then
    echo "$0 <experiment> <subject> <binary-context> <execution-context>"
fi

experiment=$1
subject=$2
binary_context=$3
execution_context=$4

function run_cql_statement() {
    statement=$1

    echo -n $statement
    cqlsh -k "phd" -e "${statement}" >/tmp/cqlshout 2>&1
    if [ $? -eq 0 ]; then
        echo " - OK"
    else
        echo " - FAILED"
        cat /tmp/cqlshout
    fi
}

run_cql_statement "delete from processes where experiment='${experiment}' and subject='${subject}' and binary='${binary_context}' and execution='${execution_context}'"
run_cql_statement "delete from processes where experiment='${experiment}' and subject='${subject}' and binary='${binary_context}' and execution='${execution_context}'"
run_cql_statement "delete from experiment_subject_binary_executions where experiment='${experiment}' and subject='${subject}' and binary='${binary_context}' and execution='${execution_context}'"
run_cql_statement "delete from process_variable_value_traces where experiment='${experiment}' and subject='${subject}' and binary='${binary_context}' and execution='${execution_context}'"
run_cql_statement "delete from subject_files where subject='${subject}'"
run_cql_statement "delete from subject_file_functions where subject='${subject}'"
run_cql_statement "delete from subject_file_function_variables where subject='${subject}'"
run_cql_statement "delete from subject_file_function_variables_by_declaration_order where subject='${subject}'"

