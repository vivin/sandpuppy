import sys
import re
import numpy
import pandas

from cassandra.cluster import Cluster
from sparklines import sparklines

from sklearn.preprocessing import minmax_scale
#from tslearn.clustering import TimeSeriesKMeans

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

    for filename in filenames:
        print("  Identifying functions in file {file}".format(file=filename))
        functions = get_subject_file_functions(session, subject, filename)
        print("  File {file} has {num} functions\n".format(file=filename, num=len(functions)))

        for function in functions:
            print("    Identifying int variables in function {function}".format(function=function))
            variables = get_subject_file_function_variables_of_type(session, subject, filename, function, 'int')
            print("    Function {function} has {num} int variables\n".format(function=function, num=len(variables)))
            if len(variables) == 0:
                continue

            for variable in variables:
                print("      Retrieving value traces for {file}::{function}::{type} {name}:{line}".format(
                    file=filename,
                    function=function,
                    type=variable['type'],
                    name=variable['name'],
                    line=variable['declared_line']
                ))

                variable['info'] = get_variable_value_traces_info(
                    session,
                    experiment,
                    subject,
                    binary,
                    execution,
                    'success',
                    filename,
                    function,
                    variable['declared_line'],
                    variable['type'],
                    variable['name']
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

            # print_variables_info(variables)

            print("")
            classified_variables = classify_variables(variables)

            if len(classified_variables['constants']) > 0:
                print("")
                print("    Constants:")
                for variable in classified_variables['constants']:
                    print("      {fqn}".format(fqn=variable['fqn']))

            if len(classified_variables['counters']) > 0:
                print("")
                print("    Counters:")
                for variable in classified_variables['counters']:
                    print("      {fqn}".format(fqn=variable['fqn']))

            if len(classified_variables['enums']) > 0:
                print("")
                print("    Enums:")
                for variable in classified_variables['enums']:
                    print("      {fqn}".format(fqn=variable['fqn']))

            if len(classified_variables['related']) > 0:
                print("")
                print("    Related variables:")
                for related in classified_variables['related']:
                    print("      {related}".format(related=[variable['fqn'] for variable in related]))

            print("")

            # TODO: next thing to do is to identify vars that are modified close together. build a map where key is
            # TODO: modified line. start with each var and see what all vars are there in modified_line - 5 to
            # TODO: modified line + 5. to see if var is related, compare the length of traces for each pid. maybe
            # TODO: making sure they are exactly the same may be too strict. check instead if the average length of
            # TODO: trace is close enough. basically both should have been modified around the same number of times.

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


def classify_variables(variables):

    classified_vars = {
        'constants': [],
        'counters': [],
        'enums': [],
        'related': []
    }
    classified_fqns = set()
    variables_by_fqn = dict()
    vars_by_modified_line = dict()
    for variable in variables:

        variables_by_fqn[variable['fqn']] = variable

        for modified_line in variable['info']['modified_lines']:
            if modified_line not in vars_by_modified_line:
                vars_by_modified_line[modified_line] = []

            vars_by_modified_line[modified_line].append(variable)

        analysis = analyze_variable(variable)
        variable['analysis'] = analysis

        if analysis['num_traces'] < 1:
            print("      Not classifying {fqn} as it has zero traces.".format(fqn=variable['fqn']))
            continue
        else:
            print("      Attempting to classify {fqn}...".format(fqn=variable['fqn']))

        if analysis['num_modified_lines'] == 1 and analysis['num_unique_values'] == 1:
            # print("      {fqn} is effectively a constant.\n".format(fqn=variable['fqn']))
            classified_vars['constants'].append(variable)
            classified_fqns.add(variable['fqn'])
            continue

        if analysis['modified_max'] <= 1:
            continue

        combined_deltas = []
        is_counter = True
        for trace in variable['info']['traces']:

            deltas = []
            index = 0
            prev_sign = 0
            while index < len(trace['items']) - 1 and is_counter:
                current_value = int(trace['items'][index]["variable_value"])
                next_value = int(trace['items'][index + 1]["variable_value"])

                delta = next_value - current_value
                if index == 0:
                    prev_sign = delta / (abs(delta) if delta != 0 else 1)

                sign = delta / (abs(delta) if delta != 0 else 1)
                if sign == prev_sign and delta > 0:
                    deltas.append(abs(delta))
                    combined_deltas.append(abs(delta))
                elif len(deltas) > 0:
                    total_delta = numpy.sum(deltas)
                    if total_delta == numpy.round(len(deltas) * numpy.mean(deltas)):
                        deltas = []
                    else:
                        is_counter = False
                else:
                    is_counter = False

                index += 1

            if not is_counter:
                break

        if is_counter and numpy.mean(combined_deltas) <= 255: # Ignore things that have huge jumps in value
            # print("      {fqn} is effectively a counter.\n".format(fqn=variable['fqn']))
            classified_vars['counters'].append(variable)
            classified_fqns.add(variable['fqn'])
            continue

        # Looking for enum-like variables. We are already looking for variables that have been modified more than
        # once. Since we are looking to maximize the combinations in the input, what can we tell about the var?
        # Let's maybe first see if there is a correlation between the number of times it is invoked and the input
        # size? So our data set we will collect will be two arrays. The array will have an entry per process trace.
        # First array will hold number of times a variable was modified. Second will hold the size of the input for
        # that process.

        times_modified = [len(trace['items']) for trace in variable['info']['traces']]
        input_sizes = [trace['input_size'] for trace in variable['info']['traces']]

        times_modified_variance = numpy.var(times_modified)
        input_sizes_variance = numpy.var(input_sizes)

        if times_modified_variance == 0 or input_sizes_variance == 0:
            # print("      Ignoring {fqn} as either variance of times modified or input sizes is zero.\n".format(
            #     fqn=variable['fqn']
            # ))
            continue

        r = numpy.corrcoef(times_modified, input_sizes)

        # We will look for Pearson coefficients greater than 0.5 to see if the number of times a variable is
        # modified is correlated with input size.

        if r[0, 1] < 0.25 or r[1, 0] < 0.25:
            # print("      Ignoring {fqn} as Pearson coefficients of correlation between number of times modified "
            #       "and input size is less than 0.25.\n".format(fqn=variable['fqn']))
            continue

        # print("      Number of times {fqn} is modified is correlated with input size "
        #       "(Pearson coefficients are {a} and {b}).".format(fqn=variable['fqn'], a=r[0, 1], b=r[1, 0]))

        variable_values = numpy.array(variable['info']['variable_values']).astype(numpy.float)
        ord_mags = [numpy.log10(v) if v > 0 else 0 for v in variable_values]

        # This is super sketch, and I probably need to mathematically prove it or something. But anyway, the
        # assumption is that these enum values come from a small set of values, and even if sequential,
        # aren't wildly different in their magnitudes. We have a limit of 255 unique values and so we don't
        # expect those to vary wildly in an enum. For example, it's not likely we will have an enum with
        # values like 0, 1, 2, and then 12355914 or something. So what we'll do is calculate the standard
        # deviation of the log10 of the values and ignore the variable if that value is greater than 1.

        if numpy.std(ord_mags) > 1:
            # print("        Ignoring because stddev of log10(values) is greater than one: {std}\n".format(
            #     std=numpy.std(ord_mags)
            # ))
            continue

        # How many places is this variable modified? We have two cases where a variable can be like an enum
        # variable:
        #
        # First:
        #   value = parsed_from_input
        #   if value is valid:
        #       enum_var = value
        #
        # Second:
        #    value = parsed_from_input
        #    if value is equal to something:
        #        enum_var = value1
        #    elsif value is equal to something else:
        #        enum_var = value2
        #
        # And so on. Basically the second case is like a switch.

        if analysis['num_modified_lines'] == 1:

            # Deal with case 1:
            # print("        {fqn} is modified on only one line".format(fqn=variable['fqn']))

            # For now we will limit ourselves to variables that have up to 255 unique values
            if analysis['num_unique_values'] <= 255:
                # print("          {fqn} has {unique} unique values. This may be an enum variable.\n".format(
                #     fqn=variable['fqn'],
                #     unique=analysis['num_unique_values']
                # ))
                classified_vars['enums'].append(variable)
                classified_fqns.add(variable['fqn'])
                continue
            # else:
                # print("           Ignoring {fqn} because it has more than 255 unique values.\n".format(
                #     fqn=variable['fqn']
                # ))

        elif analysis['num_modified_lines'] == analysis['num_unique_values']:

            # Deal with case 2. Basically the number of lines it is modified on should equal the number of
            # unique values it holds
            # print("        {fqn} is has {unique} values and is modified on the same number of lines. "
            #       "It is probably an enum variable.\n".format(fqn=variable['fqn'],
            #                                                   unique=analysis['num_unique_values']))
            classified_vars['enums'].append(variable)
            classified_fqns.add(variable['fqn'])
            continue

    # TODO: I think it is better to do it by going through each var that is not already classified, and then looking at
    # TODO: each of its modified lines, and then see what vars are also modified within -3 to +3 lines. for each
    # TODO: candidate var, make sure that it has the same number of traces as the var in question, and make sure that
    # TODO: for each process, the trace lengths are identical. you could just calculate mean and stddev to compare. if
    # TODO: they match, then vars are potentially candidate vars. I think you only need to start with one modified line
    # TODO: right? you don't need to check each one. because if the mean and stddev are equal that means they are
    # TODO: modified the same number of times.

    # TODO: add more png files so that you have a variety of height, width, color depth, etc.
    # if len(classified_fqns) > 0:
    #     print("")

    related_vars = dict()
    for variable in variables:
        if variable['fqn'] in classified_fqns:
            continue

        analysis = variable['analysis']
        if analysis['modified_max'] == 0:
            continue

        # print("      Looking for variables related to {fqn}".format(fqn=variable['fqn']))
        modified_line = list(variable['info']['modified_lines'])[0]
        candidate_vars = set()
        for delta in range(1, 6):

            previous_line = modified_line - delta
            if previous_line in vars_by_modified_line:
                modified_vars_previous_line = set(
                    [var['fqn'] for var in vars_by_modified_line[previous_line] if var['fqn'] not in classified_fqns]
                ).difference([variable['fqn']])
                if len(modified_vars_previous_line) > 0:
                    # print("        Variables modified on previous line {l} ({delta}): {vars}".format(
                    #     l=previous_line, vars=modified_vars_previous_line, delta=delta
                    # ))
                    candidate_vars = candidate_vars.union(modified_vars_previous_line)

            next_line = modified_line + delta
            if next_line in vars_by_modified_line:
                modified_vars_next_line = set(
                    [var['fqn'] for var in vars_by_modified_line[next_line] if var['fqn'] not in classified_fqns]
                ).difference([variable['fqn']])
                if len(modified_vars_next_line) > 0:
                    # print("        Variables modified on next line {l} ({delta}): {vars}".format(
                    #     l=next_line, vars=modified_vars_next_line, delta=delta
                    # ))
                    candidate_vars = candidate_vars.union(modified_vars_next_line)

        if len(candidate_vars) > 0:
            for candidate_var_name in candidate_vars:
                candidate_var = variables_by_fqn[candidate_var_name]
                candidate_var_analysis = candidate_var['analysis']

                if analysis['num_traces'] == candidate_var_analysis['num_traces'] and \
                    analysis['num_modified_lines'] == candidate_var_analysis['num_modified_lines'] and \
                    analysis['modified_max'] == candidate_var_analysis['modified_max'] and \
                    analysis['modified_min'] == candidate_var_analysis['modified_min'] and \
                    analysis['modified_mean'] == candidate_var_analysis['modified_mean'] and \
                        analysis['modified_stddev'] == candidate_var_analysis['modified_stddev']:

                    if variable['fqn'] not in related_vars:
                        related_vars[variable['fqn']] = []

                    related_vars[variable['fqn']].append(candidate_var_name)
                    # print("        {fqn} is related.".format(fqn=candidate_var_name))

        # print("")

    for related_var_name in related_vars.keys():
        if related_var_name in classified_fqns:
            continue

        related = []
        frontier = {related_var_name}
        while len(frontier) > 0:
            var_name = frontier.pop()
            related.append(var_name)
            classified_fqns.add(var_name)
            if var_name in related_vars:
                frontier = frontier.union(set([v for v in related_vars[var_name] if v not in classified_fqns]))

        classified_vars['related'].append([variables_by_fqn[fqn] for fqn in related])

    # for related in classified_vars['related']:
        # print("      Related variables: {rel}".format(rel=related))

    return classified_vars


# TODO: possible to build libpng so that it errors out on unknown chuks??
# TODO: ok i think you need to incorporate declared line and modified line. because if it is always getting
# TODO: set the same place where it is declared then it is probably not a counter maybe... uhhh fuck. i dunno.
# TODO: coz if you have a for loop you have declaration and modification on same line. so you can't tell that
# TODO: it is different from a case where you just a have a func with a variable and it just sets it to some
# TODO: value based on the argument it gets. if the argument is sort of counter like or something in it that
# TODO: has to do with counting, then this variable ends up being a proxy for it and also being a counter.
# TODO: so declared and modified line won't help i don't think. oh well. anyways. next see if you can identify
# TODO: size variables. see how value relates to input size. and then finally you can figure out the enum
# TODO: vars. limit it to variables that have max 16 unique values?? or maybe 255 unique vals. check to see if
# TODO: it is modified in one place. if it takes 255 unique vals and is set in one place then maybe it is a
# TODO: candidate. another way is if it is set in multiple places, but each place it is set to a unique value.
# TODO: and the union of all the values it gets set to at each modified location is the same as the total set of
# TODO: values the var takes on. then it is an enum var i think.
#
# TODO: how many false negatives do we have??? need to make a test program with all kinds of counters... see
# TODO: which ones aren't picked up

def analyze_variable(variable):
    analysis = dict()

    analysis['num_traces'] = len(variable['info']['traces'])
    analysis['num_modified_lines'] = len(variable['info']['modified_lines'])
    analysis['num_unique_values'] = len(set(variable['info']['variable_values']))

    trace_lengths = []
    for trace in variable['info']['traces']:
        trace_lengths.append(len(trace['items']))

    analysis['modified_min'] = numpy.min(trace_lengths) if len(trace_lengths) > 0 else 0
    analysis['modified_max'] = numpy.max(trace_lengths) if len(trace_lengths) > 0 else 0
    analysis['modified_mean'] = numpy.mean(trace_lengths) if len(trace_lengths) > 0 else 0
    analysis['modified_stddev'] = numpy.std(trace_lengths) if len(trace_lengths) > 0 else 0

    return analysis


def print_variables_info(variables):
    for variable in variables:
        print("      {fqn}".format(fqn=variable['fqn']))

        analysis = analyze_variable(variable)

        variable_values = numpy.array(variable['info']['variable_values']).astype(numpy.float)
        print("        Has {num} traces".format(num=analysis['num_traces']))
        print("        Is modified on {num} lines{line}".format(
            num=analysis['num_modified_lines'],
            line=" ({l})".format(l=list(variable['info']['modified_lines'])[0])
            if analysis['num_modified_lines'] == 1 else ""
        ))
        print("        Has {num} unique values; mean is {mean} and standard deviation is {stddev}".format(
            num=analysis['num_unique_values'],
            mean=numpy.mean(variable_values),
            stddev=numpy.std(variable_values)
        ))
        if len(set(variable_values)) > 1:
            hist = numpy.histogram(variable_values, bins=len(set(variable_values)))[0]
            for line in sparklines(hist):
                print("          {line}".format(line=line))

        print("        Is modified a minimum of {min} times and a maximum of {max} times per process".format(
            min=analysis['modified_min'],
            max=analysis['modified_max']
        ))
        print("        Is modified an average of {avg} times per process (standard deviation={stddev})".format(
            avg=analysis['modified_mean'],
            stddev=analysis['modified_stddev']
        ))

        trace_lengths = []
        for trace in variable['info']['traces']:
            trace_lengths.append(len(trace['items']))

        if len(set(trace_lengths)) > 1:
            hist = numpy.histogram(trace_lengths, bins=len(set(trace_lengths)))[0]
            for line in sparklines(hist):
                print("          {line}".format(line=line))

        if len(variable['info']['modified_lines']) > 1:
            for modified_line in variable['info']['modified_line_values']:
                print("          Has {num} unique values on line {line}; mean is {mean} and standard deviation"
                      " is {stddev}".format(
                       num=len(set(variable['info']['modified_line_values'][modified_line])),
                       line=modified_line,
                       mean=numpy.mean(numpy.array(variable['info']['modified_line_values'][modified_line])
                                       .astype(numpy.float)),
                       stddev=numpy.std(numpy.array(variable['info']['modified_line_values'][modified_line])
                                        .astype(numpy.float))))

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
            'fqn': "{filename}:{function}:{variable_type}:{variable_name}:{declared_line}".format(
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
            'variable_value': variable_value,
            'ts': row[4]
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
