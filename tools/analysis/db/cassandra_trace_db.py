import re

FETCH_SIZE = 2000


def get_experiment_subjects(session, experiment):
    statement = session.prepare("SELECT subject FROM experiment_subjects WHERE experiment = ?")
    statement.fetch_size = FETCH_SIZE

    rows = session.execute(statement, [experiment])

    subjects = []
    for row in rows:
        subjects.append(row[0])

    return subjects


def get_experiment_subject_binaries(session, experiment, subject):
    statement = session.prepare(
        "SELECT binary FROM experiment_subject_binaries "
        "WHERE experiment = ? "
        "AND subject = ?"
    )
    statement.fetch_size = FETCH_SIZE

    rows = session.execute(statement, [experiment, subject])

    binaries = []
    for row in rows:
        binaries.append(row[0])

    return binaries


def get_experiment_subject_binary_executions(session, experiment, subject, binary):
    statement = session.prepare(
        "SELECT binary FROM experiment_subject_binary_executions "
        "WHERE experiment = ? "
        "AND subject = ? "
        "AND binary = ?"
    )
    statement.fetch_size = FETCH_SIZE

    rows = session.execute(statement, [experiment, subject, binary])

    executions = []
    for row in rows:
        executions.append(row[0])

    return executions


def get_pids_with_exit_status(session, experiment, subject, binary, execution, exit_status):
    pids_statement = session.prepare(
        "SELECT pid FROM processes WHERE experiment = ? "
        "AND subject = ? "
        "AND binary = ? "
        "AND execution = ? "
        "AND exit_status = ?"
    )
    pids_statement.fetch_size = FETCH_SIZE

    rows = session.execute(pids_statement, [experiment, subject, binary, execution, exit_status])

    pids = []
    for row in rows:
        pids.append(row[0])

    return pids


def get_subject_filenames(session, subject):
    filenames_statement = session.prepare(
        "SELECT filename FROM subject_files WHERE subject = ?"
    )
    filenames_statement.fetch_size = FETCH_SIZE

    rows = session.execute(filenames_statement, [subject])

    filenames = []
    for row in rows:
        filenames.append(row[0])

    return filenames


def get_subject_file_functions(session, subject, filename):
    functions_statement = session.prepare(
        "SELECT function_name FROM subject_file_functions WHERE subject = ? AND filename = ?"
    )
    functions_statement.fetch_size = FETCH_SIZE

    rows = session.execute(functions_statement, [subject, filename])

    functions = []
    for row in rows:
        functions.append(row[0])

    return functions


def get_subject_file_function_variables_of_type(session, subject, filename, function, variable_type):
    variables_statement = session.prepare(
        "SELECT variable_type, variable_name, declared_line FROM subject_file_function_variables WHERE subject = ? "
        "AND filename = ? "
        "AND function_name = ? "
        "AND variable_type = ?"
    )
    variables_statement.fetch_size = FETCH_SIZE

    rows = session.execute(variables_statement, [subject, filename, function, variable_type])

    variables = []
    for row in rows:
        variables.append({
            'filename': filename,
            'function': function,
            'type': row[0],
            'name': row[1],
            'fqn': "{filename}::{function}::{variable_type}:{variable_name}:{declared_line}".format(
                filename=re.sub("^.*/", "", filename),
                function=function,
                variable_type=variable_type,
                variable_name=row[1],
                declared_line=row[2]
            ),
            'declared_line': row[2]
        })

    return variables


def retrieve_variable_value_traces_information(variable, session, experiment, subject, binary, execution, exit_status,
                                               filename, function):
    declared_line = variable['declared_line']
    variable_type = variable['type']
    variable_name = variable['name']

    trace_statement = session.prepare(
        "SELECT pid, input_size, modified_line, variable_value, timestamp FROM process_variable_value_traces "
        "WHERE experiment = ? "
        "AND subject = ? "
        "AND binary = ? "
        "AND execution = ? "
        "AND exit_status = ? "
        "AND filename = ? "
        "AND function_name = ? "
        "AND declared_line = ? "
        "AND variable_type = ? "
        "AND variable_name = ? "
    )
    trace_statement.fetch_size = FETCH_SIZE

    rows = session.execute(trace_statement, [experiment, subject, binary, execution, exit_status, filename, function,
                                             declared_line, variable_type, variable_name])

    traces_info = {
        'traces': [],
        'modified_lines': set(),
        'variable_values': [],
        'modified_line_values': {}
    }

    traces_by_pid = {}
    for row in rows:

        pid = row[0]
        input_size = row[1]
        if pid not in traces_by_pid:
            traces_by_pid[pid] = {
                'pid': pid,
                'input_size': input_size,
                'items': [],
                'values': []
            }

        pid_trace = traces_by_pid[pid]

        modified_line = row[2]
        variable_value = int(row[3]) if variable_type == "int" else row[3]

        pid_trace['items'].append({
            'modified_line': modified_line,
            'variable_value': variable_value,
            'ts': row[4]
        })
        pid_trace['values'].append(variable_value)

        traces_info['modified_lines'].add(modified_line)
        traces_info['variable_values'].append(variable_value)

        if modified_line not in traces_info['modified_line_values']:
            traces_info['modified_line_values'][modified_line] = []

        traces_info['modified_line_values'][modified_line].append(variable_value)

    # Need to wrap with list(...) otherwise stupid multiprocessing doesn't work
    traces_info['traces'] = list(traces_by_pid.values())
    return traces_info


def delete_experiment_subject(session, experiment, subject):
    delete = session.prepare(
        "DELETE FROM experiment_subjects "
        "WHERE experiment = ? "
        "AND subject = ?"
    )
    session.execute(delete, [experiment, subject])


def delete_experiment_subject_binary(session, experiment, subject, binary):
    delete = session.prepare(
        "DELETE FROM experiment_subject_binaries "
        "WHERE experiment = ? "
        "AND subject = ? "
        "AND binary = ?"
    )
    session.execute(delete, [experiment, subject, binary])


def delete_experiment_subject_binary_execution(session, experiment, subject, binary, execution):
    delete = session.prepare(
        "DELETE FROM experiment_subject_binary_executions "
        "WHERE experiment = ? "
        "AND subject = ? "
        "AND binary = ? "
        "AND execution = ?"
    )
    session.execute(delete, [experiment, subject, binary, execution])


def delete_subject_filename(session, subject, filename):
    delete = session.prepare(
        "DELETE FROM subject_files WHERE subject = ? AND filename = ?"
    )
    session.execute(delete, [subject, filename])


def delete_subject_file_function(session, subject, filename, function):
    delete = session.prepare(
        "DELETE FROM subject_file_functions WHERE subject = ? AND filename = ? AND function_name = ?"
    )
    session.execute(delete, [subject, filename, function])


def delete_subject_file_function_variable(session, subject, filename, function, variable_type, variable_name,
                                          declared_line):
    delete1 = session.prepare(
        "DELETE FROM subject_file_function_variables "
        "WHERE subject = ? "
        "AND filename = ? "
        "AND function_name = ? "
        "AND variable_type = ? "
        "AND variable_name = ? "
        "AND declared_line = ?"
    )
    delete2 = session.prepare(
        "DELETE FROM subject_file_function_variables_by_declaration_order "
        "WHERE subject = ? "
        "AND filename = ? "
        "AND function_name = ? "
        "AND declared_line = ? "
        "AND variable_type = ? "
        "AND variable_name = ?"
    )

    session.execute(delete1, [subject, filename, function, variable_type, variable_name, declared_line])
    session.execute(delete2, [subject, filename, function, declared_line, variable_type, variable_name])


def delete_processes(session, experiment, subject, binary, execution):
    statement = session.prepare(
        "SELECT pid FROM processes "
        "WHERE experiment = ? "
        "AND subject = ? "
        "AND binary = ? "
        "AND execution = ?"
    )
    statement.fetch_size = FETCH_SIZE

    delete = session.prepare(
        "DELETE FROM processes "
        "WHERE experiment = ? "
        "AND subject = ? "
        "AND binary = ? "
        "AND execution = ? "
        "AND pid = ?"
    )

    rows = session.execute(statement, [experiment, subject, binary, execution])
    for row in rows:
        pid = row[0]

        session.execute(delete, [experiment, subject, binary, execution, pid])


def delete_process_variable_value_traces(session, experiment, subject, binary, execution, exit_status, filename,
                                         function, declared_line, variable_type, variable_name):
    statement = session.prepare(
        "SELECT pid, timestamp, id FROM process_variable_value_traces "
        "WHERE experiment = ? "
        "AND subject = ? "
        "AND binary = ? "
        "AND execution = ? "
        "AND exit_status = ? "
        "AND filename = ? "
        "AND function_name = ? "
        "AND declared_line = ? "
        "AND variable_type = ? "
        "AND variable_name = ? "
    )
    statement.fetch_size = FETCH_SIZE

    delete = session.prepare(
        "DELETE FROM process_variable_value_traces "
        "WHERE experiment = ? "
        "AND subject = ? "
        "AND binary = ? "
        "AND execution = ? "
        "AND exit_status = ? "
        "AND filename = ? "
        "AND function_name = ? "
        "AND declared_line = ? "
        "AND variable_type = ? "
        "AND variable_name = ? "
        "AND pid = ? "
        "AND timestamp = ? "
        "AND id = ?"
    )

    rows = session.execute(statement, [experiment, subject, binary, execution, exit_status, filename, function,
                                       declared_line, variable_type, variable_name])
    for row in rows:
        pid = row[0]
        timestamp = row[1]
        id = row[2]

        session.execute(delete, [experiment, subject, binary, execution, exit_status, filename, function, declared_line,
                                 variable_type, variable_name, pid, timestamp, id])
