import sys

from cassandra.auth import PlainTextAuthProvider
from cassandra.cluster import Cluster

from db import cassandra_trace_db


def main(experiment: str, subject: str, binary: str = None, execution: str = None):
    print("Clearing data for:\n")

    print("Experiment: {experiment}".format(experiment=experiment))
    print("Subject:    {subject}".format(subject=subject))

    auth_provider = PlainTextAuthProvider(username='phd', password='phd')
    cluster = Cluster(protocol_version=4, auth_provider=auth_provider)
    session = cluster.connect('phd')

    if binary is not None:
        print("Binary:     {binary}".format(binary=binary))
        binaries = [binary]
    else:
        binaries = cassandra_trace_db.get_experiment_subject_binaries(session, experiment, subject)

    if execution is not None:
        print("Execution:  {execution}\n".format(execution=execution))
        executions = [execution]
    else:
        executions = []
        for _binary in binaries:
            executions += cassandra_trace_db.get_experiment_subject_binary_executions(
                session, experiment, subject, _binary
            )

    filenames = cassandra_trace_db.get_subject_filenames(session, subject)
    for filename in sorted(filenames):

        functions = cassandra_trace_db.get_subject_file_functions(session, subject, filename)
        for function in sorted(functions):
            variables = cassandra_trace_db.get_subject_file_function_variables_of_type(session, subject, filename,
                                                                                       function, "int")
            for variable in variables:
                variable_type = variable['type']
                variable_name = variable['name']
                declared_line = variable['declared_line']

                for _binary in binaries:
                    for _execution in executions:
                        for exit_status in ["hang", "crash", "failure", "success"]:
                            print(f"Deleting traces for {variable['fqn']} from processes of binary {_binary} during "
                                  f"execution {_execution} with exit status {exit_status}...")
                            cassandra_trace_db.delete_process_variable_value_traces(
                                session, experiment, subject, _binary, _execution, exit_status, filename, function,
                                declared_line, variable_type, variable_name
                            )
                        print("")

                if binary is None:
                    print(f"Deleting {variable['fqn']}...")
                    cassandra_trace_db.delete_subject_file_function_variable(
                        session, subject, filename, function, variable_type, variable_name, declared_line
                    )
                    print("")

            if binary is None:
                print(f"Deleting {subject}::{filename}::{function}...")
                cassandra_trace_db.delete_subject_file_function(session, subject, filename, function)
                print("")

        if binary is None:
            print(f"Deleting {subject}::{filename}..")
            cassandra_trace_db.delete_subject_filename(session, subject, filename)
            print("")

    for _binary in binaries:
        for _execution in executions:
            print(f"Deleting processes of binary {_binary} from execution {_execution}...")
            cassandra_trace_db.delete_processes(session, experiment, subject, _binary, _execution)

            print(f"Deleting execution {_execution} of binary {_binary}...")
            cassandra_trace_db.delete_experiment_subject_binary_execution(
                session, experiment, subject, _binary, _execution
            )

            print("")

        print(f"Deleting binary {_binary}...")
        cassandra_trace_db.delete_experiment_subject_binary(session, experiment, subject, _binary)

        print("")

    if binary is None:
        print(f"Deleting subject {subject}...")
        cassandra_trace_db.delete_experiment_subject(session, experiment, subject)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Syntax: {script} <experiment> <subject> [<binary> [<execution>]]".format(
            script=sys.argv[0]
        ))
    else:
        _experiment = sys.argv[1]
        _subject = sys.argv[2]

        if len(sys.argv) >= 4:
            _binary = sys.argv[3]
        else:
            _binary = None

        if len(sys.argv) == 5:
            _execution = sys.argv[4]
        else:
            _execution = None

        main(_experiment, _subject, _binary, _execution)
