import re
from itertools import zip_longest

FETCH_SIZE = 2000

DECLARED_LINE = 0
VARIABLE_TYPE = 1
VARIABLE_NAME = 2

PID = 0
INPUT_SIZE = 1

TIMESTAMP = 0
MODIFIED_LINE = 1
VARIABLE_VALUE = 2


# iterate a list in batches of size n
def batcher(iterable, n):
    args = [iter(iterable)] * n
    return zip_longest(*args)


def batched_sscan(client, key):
    batch = []
    for element_batch in batcher(client.sscan_iter(key), 500):
        batch.extend([x.decode("utf-8") for x in element_batch if x is not None])

    return batch


def get_subject_filenames(client, subject):
    return batched_sscan(client, f"{subject}.files")


def get_subject_file_functions(client, subject, filename):
    return batched_sscan(client, f"{subject}:{filename}.functions")


def get_subject_file_function_variables_of_type(client, subject, filename, function, variable_type):
    variable_entries = batched_sscan(client, f"{subject}:{filename}:{function}.variables")

    variables = []
    for variable_entry in variable_entries:
        variable_fields = variable_entry.split(",")
        if variable_fields[VARIABLE_TYPE] == variable_type:
            variables.append({
                'filename': filename,
                'function': function,
                'type': variable_type,
                'name': variable_fields[VARIABLE_NAME],
                'fqn': "{filename}::{function}::{variable_type}:{variable_name}:{declared_line}".format(
                    filename=re.sub("^.*/", "", filename),
                    function=function,
                    variable_type=variable_type,
                    variable_name=variable_fields[VARIABLE_NAME],
                    declared_line=variable_fields[DECLARED_LINE]
                ),
                'declared_line': variable_fields[DECLARED_LINE]
            })

    return variables


def retrieve_variable_value_traces_information(variable, client, experiment, subject, binary, execution, exit_status,
                                               filename, function):
    declared_line = variable['declared_line']
    variable_type = variable['type']
    variable_name = variable['name']

    pid_info_entries = batched_sscan(client, f"{experiment}:{subject}:{binary}:{execution}:{filename}:{function}:"
                                             f"{declared_line}:{variable_type}:{variable_name}:{exit_status}")

    traces_info = {
        'traces': [],
        'modified_lines': set(),
        'variable_values': []
        #'modified_line_values': {}
    }

    traces_by_pid = {}
    for pid_info_entry in pid_info_entries:
        pid_info = pid_info_entry.split(",")

        pid_trace = {
            'pid': pid_info[PID],
            'input_size': int(pid_info[INPUT_SIZE]),
            'items': [],
            'values': []
        }

        pid_variable_value_trace_entries = batched_sscan(client, f"{experiment}:{subject}:{binary}:{execution}:"
                                                                 f"{filename}:{function}:{declared_line}:"
                                                                 f"{variable_type}:{variable_name}:{pid_info[PID]}")
        pid_variable_value_trace_entries.sort()
        for pid_variable_value_trace_entry in pid_variable_value_trace_entries:

            pid_variable_value_trace = pid_variable_value_trace_entry.split(",")
            modified_line = int(pid_variable_value_trace[MODIFIED_LINE])
            variable_value = int(pid_variable_value_trace[VARIABLE_VALUE])\
                if variable_type == "int" else pid_variable_value_trace[VARIABLE_VALUE]

            pid_trace['items'].append({
                'modified_line': modified_line,
                'variable_value': variable_value,
                'ts': int(pid_variable_value_trace[TIMESTAMP])
            })
            pid_trace['values'].append(variable_value)

            traces_info['modified_lines'].add(modified_line)
            traces_info['variable_values'].append(variable_value)

            # if modified_line not in traces_info['modified_line_values']:
            #     traces_info['modified_line_values'][modified_line] = []
            #
            # traces_info['modified_line_values'][modified_line].append(variable_value)

        traces_by_pid[pid_info[PID]] = pid_trace

    # Need to wrap with list(...) otherwise stupid multiprocessing doesn't work
    traces_info['traces'] = list(traces_by_pid.values())
    return traces_info


def delete_experiment_subject_binary(client, experiment, subject, binary):
    count = 1
    for keybatch in batcher(client.scan_iter(f"{experiment}:{subject}:{binary}:*"), 500):
        print(f"Deleting batch {count}...")
        client.delete(*keybatch)
        count += 1


def delete_experiment_subject_binary_execution(client, experiment, subject, binary, execution):
    count = 1
    for keybatch in batcher(client.scan_iter(f"{experiment}:{subject}:{binary}:{execution}:*"), 500):
        print(f"Deleting batch {count}...")
        client.delete(*keybatch)
        count += 1
