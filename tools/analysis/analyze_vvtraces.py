import sys

from cassandra.cluster import Cluster

FETCH_SIZE = 2000


def main(experiment, subject, binary, execution):
    cluster = Cluster(protocol_version=4)
    session = cluster.connect('phd')

    print("Starting analysis of variable value traces\n")

    print("Experiment: {experiment}".format(experiment=experiment))
    print("Subject:    {subject}".format(subject=subject))
    print("Binary:     {binary}".format(binary=binary))
    print("Execution:  {execution}\n".format(execution=execution))

    print("Identifying files for subject {subject}".format(subject=subject))
    filenames = get_subject_filenames(session, subject)
    print("Subject {subject} has {num} files\n".format(subject=subject, num=len(filenames)))

    for filename in filenames:
        print("  Identifying functions in file {file}".format(file=filename))
        functions = get_subject_file_functions(session, subject, filename)
        print("  File {file} has {num} functions\n".format(file=filename, num=len(functions)))

        for function in functions:
            print("    Identifying int variables in function {function}".format(function=function))
            variables = get_subject_file_function_variables_of_type(session, subject, filename, function, 'int')
            print("    Function {function} has {num} int variables\n".format(function=function, num=len(variables)))

            for variable in variables:
                print("      Analyzing value traces for {file}::{function}::{type} {name}:{line}".format(
                    file=filename,
                    function=function,
                    type=variable["type"],
                    name=variable["name"],
                    line=variable["declared_line"]
                ))

                variable["traces"] = get_variable_value_traces(
                    session,
                    experiment,
                    subject,
                    binary,
                    execution,
                    'success',
                    filename,
                    function,
                    variable["declared_line"],
                    variable["type"],
                    variable["name"]
                )

                # This is where you can start analyzing all these traces. Pass this information into another
                # function and you can put it into a pandas dataframe I think. Then you can do things like graph
                # a histogram or maybe heatmap of values the variable takes on where it is declared and then each
                # line where it is modified. You can also draw a 3d "path" where x coordinate is the delta between
                # declared line and modified line, y coordinate is the value, and z is a time coordinate that
                # increases strictly monotonically (we get traces back in ascending order of time anyway so this is
                # easy to do). You could potentially graph a bunch of these traces together, but you may need to
                # normalize both deltas and values. That is if you are graphing multiple variables at the same time.
                # For the same variable you may not need to. Experiment and see.

                print("      {file}::{function}::{type} {name}:{line} has {num} traces".format(
                    file=filename,
                    function=function,
                    type=variable["type"],
                    name=variable["name"],
                    line=variable["declared_line"],
                    num=len(variable["traces"])
                ))

            print("")


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
            'type': row[0],
            'name': row[1],
            'declared_line': row[2]
        })

    return variables


def get_variable_value_traces(session, experiment, subject, binary, execution, exit_status, filename, function,
                              declared_line, variable_type, variable_name):
    trace_statement = session.prepare(
        "SELECT pid, input_size, modified_line, variable_value FROM process_variable_value_traces WHERE experiment = ? "
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

    last_pid = None
    trace = None
    traces = []
    for row in rows:
        pid = row[0]
        if pid != last_pid:
            if trace is not None:
                traces.append(trace)
            trace = []

        trace.append({
            'input_size': row[1],
            'modified_line': row[2],
            'variable_value': row[3]
        })

        last_pid = pid

    return traces


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Syntax: {script} <experiment> <subject> <binary> <execution>".format(script=sys.argv[0]))
    else:
        main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
