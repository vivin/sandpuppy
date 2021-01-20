import sys
import re
import numpy
import pandas

from cassandra.cluster import Cluster
from sparklines import sparklines

from sklearn.preprocessing import minmax_scale
from tslearn.clustering import TimeSeriesKMeans

FETCH_SIZE = 2000


# TODO: in the vvdump instrumenter maybe you can only focus on int. would result in much less traces.


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

    # each element is a dict. has two fields: name and trace. trace is a list of arrays:
    # [value, modified - declared]. name is the fully qualified name of the variable.
    all_traces = []

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

                variable["info"] = get_variable_value_traces_info(
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

                # Try KNN with dynamic time warping. I think you will have to normalize every value in a trace with
                # respect to the trace itself (so that everything is between 0 and 1). This includes the "distance"
                # metric (modified - declared). I think using this you should be able to classify families of traces.

                variable_values = numpy.array(variable["info"]["variable_values"]).astype(numpy.float)

                print("        Has {num} traces".format(
                    num=len(variable["info"]["traces"])
                ))
                print("        Is modified on {num} lines{line}".format(
                    num=len(variable["info"]["modified_lines"]),
                    line=" ({l})".format(l=list(variable["info"]["modified_lines"])[0])
                    if len(variable["info"]["modified_lines"]) == 1 else ""
                ))

                print("        Has {num} unique values; mean is {mean} and standard deviation is {stddev}".format(
                    num=len(set(variable_values)),
                    mean=numpy.mean(variable_values),
                    stddev=numpy.std(variable_values)
                ))

                if len(set(variable_values)) > 1:
                    hist = numpy.histogram(variable_values, bins=len(set(variable_values)))[0]
                    for line in sparklines(hist):
                        print("          {line}".format(line=line))

                trace_lengths = []
                for trace in variable["info"]["traces"]:
                    trace_lengths.append(len(trace["items"]))

                    trace_items = []
                    t = 0
                    for trace_item in trace["items"]:
                        #trace_items.append([
                        #    int(trace_item["variable_value"]),
                        #    trace_item["modified_line"] - variable["declared_line"]
                        #])
                        trace_items.append(int(trace_item["variable_value"]))

                        t += 1

                    all_traces.append({
                        'name': variable["fqn"],
                        'trace': minmax_scale(trace_items)      # MinMaxScaler().fit_transform(trace_items)
                    })

                print("        Is modified a minimum of {min} times and a maximum of {max} times per process".format(
                    min=numpy.min(trace_lengths),
                    max=numpy.max(trace_lengths)
                ))
                print("        Is modified an average of {avg} times per process (standard deviation={stddev})".format(
                    avg=numpy.mean(trace_lengths),
                    stddev=numpy.std(trace_lengths)
                ))
                if len(set(trace_lengths)) > 1:
                    hist = numpy.histogram(trace_lengths, bins=len(set(trace_lengths)))[0]
                    for line in sparklines(hist):
                        print("          {line}".format(line=line))

                if len(variable["info"]["modified_lines"]) > 1:
                    for modified_line in variable["info"]["modified_line_values"]:
                        print("          Has {num} unique values on line {line}; mean is {mean} and standard deviation"
                              " is {stddev}".format(
                                num=len(set(variable["info"]["modified_line_values"][modified_line])),
                                line=modified_line,
                                mean=numpy.mean(numpy.array(variable["info"]["modified_line_values"][modified_line])
                                                .astype(numpy.float)),
                                stddev=numpy.std(numpy.array(variable["info"]["modified_line_values"][modified_line])
                                                 .astype(numpy.float))))

                print("")

    # TODO: ok, so just see if you can cluster using just values. the timeseries kmeans expects the data to be in some
    # TODO: weird fucking format. like a single series with the values 1, 2, 3 should be [[1],[2],[3]] or some shit??
    # TODO: then to cluster you need [ [[1], [2], [3]], [[4], [5], [6]] ] for multiple series. ugh.
    # TODO: figure out multidimensional dynamic time warping. this way you can include modified-declared. but these
    # TODO: "shapes" of the path won't really describe a "family" for enum type variables. it can for counters though.
    # TODO: this is because a path can be any path representing a unique combination of values. don't spend too much
    # TODO: time on this. start out with the manual approaches described below and then do this later.
    #
    # TODO: so how many classes of vars do we even have? we just have "counter". can't classify enums directly. but
    # TODO: may be possible to do based on manual calculation of values. also counter class is same as loop variable
    # TODO: we could tell a variable is a size variable maybe, by comparing to input size? those are the only types
    # TODO: of int variables we have. can't think of anything else. oh yeah... something could be an index. but how
    # TODO: do we tell? can't really tell (but can tell from source). so don't worry about index. so that is basically
    # TODO: it. we can filter out counters and loop variables. oh and constants too. filter those out.
    #
    # TODO: that is all we can classify and i don't know if we can really do it with time series classification or
    # TODO: something like that. will probably be manual.
    #
    # TODO: look at which variables are modified close together (as in location). for testbed, provide a "maze" program.
    # TODO: input is just u d l r which moves the character. you can instrument a "hash" that takes the hash of two
    # TODO: variables (or more). but it has to be in a way that hash(x, y) != hash(y, x).
    #
    # TODO: other things you can do: compare trace of variable with trace of another variable. see if one is proper
    # TODO: subset maybe? compare timestampts too?

    df = pandas.DataFrame(all_traces)
    combined_value_traces = numpy.array(df['trace'].values)

    print(combined_value_traces)
    model = TimeSeriesKMeans(n_clusters=3, metric="dtw", max_iter=10)
    model.fit(combined_value_traces)

    print(model.labels_)
    print(model.cluster_centers_)


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
            'fqn' : "{filename}:{function}:{variable_type}:{variable_name}:{declared_line}".format(
                filename=re.sub("^.*/", "", filename),
                function=function,
                variable_type=variable_type,
                variable_name=row[1],
                declared_line=row[2]
            ),
            'declared_line': row[2]
        })

    return variables


def get_variable_value_traces_info(session, experiment, subject, binary, execution, exit_status, filename, function,
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

    info = {
        'traces': [],
        'pid_traces': dict(),
        'modified_lines': set(),
        'variable_values': [],
        'modified_line_values': dict()
    }

    for row in rows:
        pid = row[0]
        if pid not in info["pid_traces"]:
            info["pid_traces"][pid] = {
                'items': []
            }

        input_size = row[1]
        modified_line = row[2]
        variable_value = row[3]

        info['pid_traces'][pid]['input_size'] = input_size
        info['pid_traces'][pid]['items'].append({
            'modified_line': modified_line,
            'variable_value': variable_value
        })

        info['modified_lines'].add(modified_line)
        info['variable_values'].append(variable_value)

        if modified_line not in info['modified_line_values']:
            info['modified_line_values'][modified_line] = []

        info['modified_line_values'][modified_line].append(variable_value)

    info['traces'] = info['pid_traces'].values()

    return info


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Syntax: {script} <experiment> <subject> <binary> <execution>".format(script=sys.argv[0]))
    else:
        main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
