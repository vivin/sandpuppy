import sys
import os
import numpy
import pandas
import warnings

from cassandra.cluster import Cluster
from sparklines import sparklines

from db import cassandra_trace_db
from ml import features, classifiers
from graphs import graph

from sklearn.preprocessing import minmax_scale

# from tslearn.clustering import TimeSeriesKMeans


warnings.filterwarnings('error')

BASE_PATH = "/home/vivin/Projects/phd"
BASE_WORKSPACE_PATH = f"{BASE_PATH}/workspace"

# TODO: it is decently accurate, but with the new "jaggedness" measures there seem to be some inconsistencies. But they
# TODO: are all around things that could be counters or enums. So try plotting 3d graph of everything that is not a
# TODO: constant. Plot lsp, J_full (normalized), and li_ac_full. Color by identified class. Then plot with those that
# TODO: don't have varying deltas. Then plot another with only varying deltas.
# TODO: double check your deltas and plots for the variables. Maybe you should write something to just plot the curves
# TODO: of their values. Make a graph per function. Only counter variables and enums. You could do a graph per variable
# TODO: but that would be a lot! When you plot the smoothed and unsmoothed curves you can at least make sure that
# TODO: you are actually getting all the values properly. easy way to do this is to attach the values (smoothed and
# TODO: unsmoothed) and the deltas (smoothed and unsmoothed) to the features in the variables. then you can just
# TODO: plot it from the main program. maybe pass it off to a thread.
# TODO: one way to classify counters vs enum. first check if round(l1_ac_full) is >= 0.5. if it is, then check
# TODO: round(l1_ac_filtered); this should have a higher threshold. maybe 0.75 or 0.85. if above this it is a counter
# TODO: otherwise enum. (but there are some vars that meet these thresholds but aren't counters...??) graph l1_ac_full
# TODO: vs l1_ac_filtered and see what that looks like. include counters and enums.


def features_string(var):
    general_features = var['features']['general']
    counter_features = var['features']['counter']
    enum_features = var['features']['enum']

    features_str = " (varying deltas)" if counter_features['varying_deltas'] else ""
    features_str += "\n          lsp=" + str(counter_features['loop_sequence_proportion'])
    features_str += "\n          lspf=" + str(counter_features['loop_sequence_proportion_filtered'])
    features_str += "\n          average_delta=" + str(counter_features['average_delta'])
    features_str += "\n          average_trace_length=" + str(general_features['times_modified_mean'])
    features_str += "\n          avscr=" + str(counter_features['average_value_set_cardinality_ratio'])
    features_str += "\n          tmisc=" + str(enum_features['times_modified_to_input_size_correlation'])
    features_str += "\n          mvisc=" + str(counter_features['max_value_to_input_size_correlation'])
    features_str += "\n          J_full=" + str(counter_features['jaggedness_full'])
    features_str += "\n          J_filtered=" + str(counter_features['jaggedness_filtered'])
    features_str += "\n          l1_ac_full=" + str(counter_features['lag_one_autocorr_full'])
    features_str += "\n          l1_ac_filtered=" + str(counter_features['lag_one_autocorr_filtered'])
    features_str += "\n"

    return features_str


def main(experiment: str, subject: str, binary: str, execution: str):
    cluster = Cluster(protocol_version=4)
    session = cluster.connect('phd')

    print("Starting analysis of variable value traces\n")

    print("Experiment: {experiment}".format(experiment=experiment))
    print("Subject:    {subject}".format(subject=subject))
    print("Binary:     {binary}".format(binary=binary))
    print("Execution:  {execution}\n".format(execution=execution))

    base_results_path = f"{BASE_WORKSPACE_PATH}/{experiment}/{subject}/results/{execution}"
    if not os.path.isdir(base_results_path):
        raise Exception(f"Could not find results directory at {base_results_path}")

    base_graphs_path = f"{base_results_path}/graphs"
    if not os.path.isdir(base_graphs_path):
        os.makedirs(base_graphs_path)

    all_classified_variables = []
    filenames = cassandra_trace_db.get_subject_filenames(session, subject)
    print("Subject {subject} has {num} files\n".format(subject=subject, num=len(filenames)))

    for filename in filenames:
        # print("  Identifying functions in file {file}".format(file=filename))
        functions = cassandra_trace_db.get_subject_file_functions(session, subject, filename)
        print("  File {file} has {num} functions\n".format(file=filename, num=len(functions)))

        for function in functions:
            # print("    Identifying int variables in function {function}".format(function=function))
            variables = cassandra_trace_db.get_subject_file_function_variables_of_type(session, subject, filename,
                                                                                       function, 'int')
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

                cassandra_trace_db.populate_variable_value_traces(
                    variable,
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
                    print("      {fqn}{f}".format(fqn=variable['fqn'], f=features_string(variable)))

            if len(classified_variables['correlated_with_input_size']) > 0:
                print("")
                print("    Variables correlated with input size:")
                for variable in classified_variables['correlated_with_input_size']:
                    print("      {fqn}{f}".format(fqn=variable['fqn'], f=features_string(variable)))

            if len(classified_variables['static_counters']) > 0:
                print("")
                print("    Static Counters:")
                for variable in classified_variables['static_counters']:
                    print("      {fqn}{f}".format(fqn=variable['fqn'], f=features_string(variable)))

            if len(classified_variables['dynamic_counters']) > 0:
                print("")
                print("    Dynamic Counters:")
                for variable in classified_variables['dynamic_counters']:
                    print("      {fqn}{f}".format(fqn=variable['fqn'], f=features_string(variable)))

            if len(classified_variables['input_size_counters']) > 0:
                print("")
                print("    Counters correlated with input size:")
                for variable in classified_variables['input_size_counters']:
                    print("      {fqn}{f}".format(fqn=variable['fqn'], f=features_string(variable)))

            if len(classified_variables['enums']) > 0:
                print("")
                print("    Enums:")
                for variable in classified_variables['enums']:
                    print("      {fqn}{f}".format(fqn=variable['fqn'], f=features_string(variable)))

            if len(classified_variables['related']) > 0:
                print("")
                print("    Related variables:")
                for related in classified_variables['related']:
                    print("      {related}".format(related=sorted([variable['fqn'] for variable in related])))

            print("")

            all_classified_variables += [
                {'class': v['class'], 'fqn': v['fqn'], 'features': v['features']}
                for v in variables if 'class' in v and v['class'] != 'zero_traces'
            ]

    graph.graph_counters(base_graphs_path, all_classified_variables)
    graph.graph_counters_and_enums(base_graphs_path, all_classified_variables)

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
    # TODO: other things you can do: compare trace of variable with trace of another variable. see if one is proper
    # TODO: subset maybe? compare timestampts too?


def classify_variables(variables):

    classified_vars = {
        'correlated_with_input_size': [],
        'constants': [],
        'static_counters': [],
        'dynamic_counters': [],
        'input_size_counters': [],
        'enums': [],
        'related': []
    }

    variables_by_fqn = dict()
    variables_by_modified_line = dict()
    for variable in variables:

        features.derive_general_features(variable)
        general_features = variable['features']['general']

        if general_features['num_traces'] < 1:
            print("      Not classifying {fqn} as it has zero traces.".format(fqn=variable['fqn']))
            variable['class'] = "zero_traces"
            continue
        else:
            print("      Attempting to classify {fqn}...".format(fqn=variable['fqn']))

        features.derive_input_size_correlation_features(variable)
        features.derive_counter_features(variable)
        features.derive_enum_features(variable)

        if classifiers.is_constant(variable):
            if classifiers.is_correlated_with_input_size(variable):
                variable['class'] = "correlated_with_input_size"
                classified_vars['correlated_with_input_size'].append(variable)
            else:
                variable['class'] = "constant"
                classified_vars['constants'].append(variable)
        elif classifiers.is_counter(variable):
            # Some counters with varying deltas may actually be enums, so let's check for that. But some legitimate
            # counters with varying deltas could end up being mis-classified as enums (the classification boundary
            # between counters and enums is kind of fuzzy if you think about it). So let's only try and classify
            # something with varying deltas as an enum if its loop sequence proportion is less than 0.9 or if the
            # correlation between the number of times the variable was modified and the input size is greater than or
            # equal to 0.75.
            # TODO: a better way to do this might be to calculate shannon entropy...?? do it over entire trace
            # TODO: sequence or maybe calculate average of entropy? what you need to do is calculate it over
            # TODO: a sequence of deltas ... then counters will have stuff like 1 1 1 1 0 0 1 1 1 etc. get the
            # TODO: deltas and then go through and cap the max at 255 (so anything > 255 gets set to 255). experiment
            # TODO: with two ways. either calculate the deltas on the filtered and cleaned up traces, or do it on all
            # TODO: of them... maybe this is something you do before you classify as counter? anyway play around with
            # TODO: it. if you are not dealing with cleaned up traces there can be runs of values and so your set of
            # TODO: values is from 0 to 255, which means probability each one is 1/256. if you are dealing with cleaned
            # TODO: up values then the set of values is from 1 to 255, which means probability of each one is 1/255.
            # TODO: so calculate based on that. higher entropy means it is more likely to be an enum rather than a
            # TODO: counter. even the loop sequences for varying deltas should have much more entropy compared to
            # TODO: an actual counter with varying deltas... maybe?? anyways try it out. combine this with the current
            # TODO: check maybe. maybe print out the entropy for each var?
            counter_features = variable['features']['counter']
            enum_features = variable['features']['enum']
            if counter_features['varying_deltas'] \
                and (counter_features['loop_sequence_proportion'] < 0.9 or
                     enum_features['times_modified_to_input_size_correlation'] >= 0.75) \
                    and classifiers.is_enum(variable):
                variable['class'] = "enum"
                classified_vars['enums'].append(variable)
            else:
                counter_class = classifiers.classify_counter(variable)
                variable['class'] = counter_class + "_counter"
                classified_vars[counter_class + "_counters"].append(variable)
        elif classifiers.is_enum(variable):
            variable['class'] = "enum"
            classified_vars['enums'].append(variable)
        elif classifiers.is_correlated_with_input_size(variable):
            variable['class'] = "correlated_with_input_size"
            classified_vars['correlated_with_input_size'].append(variable)

        # While classifying let's build up these dicts because we will use them when identifying related variables.
        # variables_by_fqn is for easy lookup of variables by the fully-qualified name. variables_by_modified_line is
        # to look up variables that are modified on a particular line.
        variables_by_fqn[variable['fqn']] = variable

        for modified_line in variable['info']['modified_lines']:
            if modified_line not in variables_by_modified_line:
                variables_by_modified_line[modified_line] = []

            variables_by_modified_line[modified_line].append(variable)

    related_vars = dict()
    for variable in variables:
        # If the variable has zero traces or is a constant, ignore it.
        if 'class' in variable and (variable['class'] == 'zero_traces' or variable['class'] == 'constant'):
            continue

        general_features = variable['features']['general']

        # print("      Looking for variables related to {fqn}".format(fqn=variable['fqn']))

        # The idea is that related variables will all be modified close to each other, if they are at all. Meaning that
        # if a variable is modified on multiple lines, those variables that are related to it will also be modified the
        # same number of times, close to the original variable. This means that we don't have to scan for related
        # variables at every location that the variable is modified. We can just pick one location and then scan for
        # other variables that are modified within five lines before and after this variable. Note that the variables
        # identified here may not necessarily be related even though they are modified close by. We need to perform some
        # additional checks to make sure they actually are related.

        modified_line = list(variable['info']['modified_lines'])[0]
        candidate_vars = set()
        for delta in range(1, 6):
            for line in [modified_line - delta, modified_line + delta]:
                if line in variables_by_modified_line:
                    vars_modified_on_line = set([
                        var['fqn'] for var in variables_by_modified_line[line]
                        if 'class' not in var or ('class' in var and var['class'] != 'constant')
                    ]).difference([variable['fqn']])
                    if len(vars_modified_on_line) > 0:
                        # print("        Variables modified on line {l} ({delta}): {vars}".format(
                        #     l=line, vars=vars_modified_on_line, delta=delta
                        # ))
                        candidate_vars = candidate_vars.union(vars_modified_on_line)

        # If we identified any variables that are modified close to the current variable we're looking at, we perform
        # some additional checks to make sure that they actually are related. In particular, for a given candidate
        # variable, we make sure that the following features are identical to the current variable:
        #
        #  - total number of traces
        #  - number of lines where the variable is modified
        #  - maximum number of times the variable is modified
        #  - minimum number of times the variable is modified
        #  - the mean number of times the variable is modified
        #  - the standard deviation of the number of times the variable is modified
        #
        # Only if all these features match, is a candidate variable considered to be related to the current variable.
        #
        # For each variable, we maintain a list of related variables.

        if len(candidate_vars) > 0:
            for candidate_var_name in candidate_vars:
                candidate_var = variables_by_fqn[candidate_var_name]
                candidate_general_features = candidate_var['features']['general']

                if general_features['num_traces'] == candidate_general_features['num_traces'] and \
                    general_features['num_modified_lines'] == candidate_general_features['num_modified_lines'] and \
                    general_features['times_modified_max'] == candidate_general_features['times_modified_max'] and \
                    general_features['times_modified_min'] == candidate_general_features['times_modified_min'] and \
                    general_features['times_modified_mean'] == candidate_general_features['times_modified_mean'] and \
                        general_features['times_modified_stddev'] == candidate_general_features['times_modified_stddev']:

                    if variable['fqn'] not in related_vars:
                        related_vars[variable['fqn']] = []

                    related_vars[variable['fqn']].append(candidate_var_name)
                    # print("        {fqn} is related.".format(fqn=candidate_var_name))

    # We assume that the "related to" relationship is transitive. Meaning that if a is related to b and b is related to
    # c, then a is related to c. So the full set of variables related to a is {b, c}. The following loop basically
    # traverses the "relationship graph" so that we can get the complete set of related variables. The reason that we
    # have to do this is because we only scan for a fixed number of lines before and after a variable's modified line to
    # identify potentially related variables. So while b may be modified within [-5, +5] with respect to a, c may not
    # be. However c could be modified within [-5, +5] with respect to b.

    visited = set()
    for related_var_name in related_vars.keys():
        # if 'class' in variables_by_fqn[related_var_name]:
        #     continue

        if related_var_name in visited:
            continue

        related = set()
        frontier = {related_var_name}
        while len(frontier) > 0:
            var_name = frontier.pop()
            visited.add(var_name)
            related.add(var_name)

            if var_name in related_vars:
                frontier = frontier.union(set(
                    [v for v in related_vars[var_name] if v not in visited]
                ))

        classified_vars['related'].append([variables_by_fqn[fqn] for fqn in related])

    return classified_vars


def print_variables_info(variables):
    for variable in variables:
        print("      {fqn}".format(fqn=variable['fqn']))

        features.derive_general_features(variable)
        general_features = variable['features']['general']

        variable_values = numpy.array(variable['info']['variable_values']).astype(numpy.float)
        print("        Has {num} traces".format(num=general_features['num_traces']))
        print("        Is modified on {num} lines{line}".format(
            num=general_features['num_modified_lines'],
            line=" ({l})".format(l=list(variable['info']['modified_lines'])[0])
            if general_features['num_modified_lines'] == 1 else ""
        ))
        print("        Has {num} unique values; mean is {mean} and standard deviation is {stddev}".format(
            num=general_features['num_unique_values'],
            mean=numpy.mean(variable_values),
            stddev=numpy.std(variable_values)
        ))
        if len(set(variable_values)) > 1:
            hist = numpy.histogram(variable_values, bins=len(set(variable_values)))[0]
            for line in sparklines(hist):
                print("          {line}".format(line=line))

        print("        Is modified a minimum of {min} times and a maximum of {max} times per process".format(
            min=general_features['times_modified_min'],
            max=general_features['times_modified_max']
        ))
        print("        Is modified an average of {avg} times per process (standard deviation={stddev})".format(
            avg=general_features['times_modified_mean'],
            stddev=general_features['times_modified_stddev']
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


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Syntax: {script} <experiment> <subject> <binary> <execution>".format(script=sys.argv[0]))
    else:
        main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
