import sys
import os
import warnings
from datetime import datetime
import concurrent.futures

from cassandra.cluster import Cluster

from db import cassandra_trace_db
from ml import feature_extractor, classifiers
from graphs import graph

warnings.filterwarnings('error')

BASE_PATH = "/home/vivin/Projects/phd"
BASE_WORKSPACE_PATH = f"{BASE_PATH}/workspace"


def features_string(var):
    var_features = var['features']

    features_str = " (varying deltas)" if var_features['varying_deltas'] else ""
    features_str += "\n          num_unique_values=" + str(var_features['num_unique_values'])
    features_str += "\n          lsp=" + str(var_features['loop_sequence_proportion'])
    features_str += "\n          lspf=" + str(var_features['loop_sequence_proportion_filtered'])
    features_str += "\n          average_delta=" + str(var_features['average_delta'])
    features_str += "\n          average_trace_length=" + str(var_features['times_modified_mean'])
    features_str += "\n          avscr=" + str(var_features['average_value_set_cardinality_ratio'])
    features_str += "\n          tmisc=" + str(var_features['times_modified_to_input_size_correlation'])
    features_str += "\n          mvisc=" + str(var_features['max_value_to_input_size_correlation'])
    features_str += "\n          acsl=" + str(var_features['average_counter_segment_length'])
    features_str += "\n          acslf=" + str(var_features['average_counter_segment_length_filtered'])
    features_str += "\n          sd_roughness=" + str(var_features['second_difference_roughness'])
    features_str += "\n          sd_roughness_filtered=" + str(var_features['second_difference_roughness_filtered'])
    features_str += "\n          l1_ac_full=" + str(var_features['lag_one_autocorr_full'])
    features_str += "\n          l1_ac_filtered=" + str(var_features['lag_one_autocorr_filtered'])
    features_str += "\n"

    return features_str


def main(experiment: str, subject: str, binary: str, execution: str):
    start_time = datetime.now()

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

    print("Identifying files, functions, and variables...")

    all_classified_variables = []
    filenames = cassandra_trace_db.get_subject_filenames(session, subject)

    variables_by_filename_and_function = {}
    retrieved_variables = []
    for filename in sorted(filenames):
        variables_by_filename_and_function[filename] = {}

        functions = cassandra_trace_db.get_subject_file_functions(session, subject, filename)
        for function in sorted(functions):
            variables = cassandra_trace_db.get_subject_file_function_variables_of_type(session, subject, filename,
                                                                                       function, "int")
            variables_by_filename_and_function[filename][function] = {
                'variables': variables,
                'zero_traces': [],
                'constant': [],
                'correlated_with_input_size': [],
                'boolean': [],
                'static_counter': [],
                'dynamic_counter': [],
                'input_size_counter': [],
                'enum': [],
                'enum_value_from_input': [],
                'unknown': [],
                'related': []
            }

            retrieved_variables += variables

    num_retrieved_variables = len(retrieved_variables)
    print(f"Retrieving traces for {num_retrieved_variables} variables and classifying...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=60) as thread_pool_executor,\
         concurrent.futures.ProcessPoolExecutor(max_workers=12) as process_pool_executor:

        # Retrieve traces for all variables in parallel
        traces_info_future_to_variable = {
            thread_pool_executor.submit(
                cassandra_trace_db.retrieve_variable_value_traces_information,
                variable=variable,
                session=session,
                experiment=experiment,
                subject=subject,
                binary=binary,
                execution=execution,
                exit_status='success',
                filename=variable['filename'],
                function=variable['function']
            ): variable for variable in retrieved_variables
        }

        thread_pool_executor.shutdown(wait=False)

        # As each traces-query completes, populate the corresponding variable with the retrieved traces and classify
        # in parallel
        counts = {'processed': 0}
        for traces_info_future in concurrent.futures.as_completed(traces_info_future_to_variable):
            variable = traces_info_future_to_variable[traces_info_future]
            variable['traces_info'] = traces_info_future.result()

            # Delete the entry in the map and delete the future
            del traces_info_future_to_variable[traces_info_future]
            del traces_info_future

            def callback(future, variable=variable):
                counts['processed'] += 1
                print("." if counts['processed'] % 10 != 0 else counts['processed'], end='', flush=True)

                features, variable_class = future.result()
                variable['features'] = features
                variable['class'] = variable_class

                _filename = variable['filename']
                _function = variable['function']
                variables_by_filename_and_function[_filename][_function][variable_class].append(variable)

                # Delete the list of traces and variable values because we no longer need it. This should also free
                # up memory
                del variable['traces_info']['traces']
                del variable['traces_info']['variable_values']

            classify_future = process_pool_executor.submit(classify_variable, variable)
            classify_future.add_done_callback(callback)

        process_pool_executor.shutdown(wait=True)

    print("\n")

    # Now identify related variables for each function in each filename
    for filename in sorted(variables_by_filename_and_function.keys()):
        for function in sorted(variables_by_filename_and_function[filename].keys()):
            variables_by_filename_and_function[filename][function]['related'] = identify_related_variables(
                filename,
                function,
                variables_by_filename_and_function
            )

    print("")
    labels_to_description = {
        'constant': "Constants",
        'correlated_with_input_size': "Variables correlated with input size",
        'boolean': "Booleans",
        'static_counter': "Static Counters",
        'dynamic_counter': "Dynamic Counters",
        'input_size_counter': "Counters correlated with input size",
        'enum': "Enums",
        'enum_value_from_input': "Enums deriving value from input",
        'related': "Related variables"
    }

    for filename in sorted(variables_by_filename_and_function.keys()):
        for function in sorted(variables_by_filename_and_function[filename].keys()):
            function_variables = variables_by_filename_and_function[filename][function]

            for label in ['constant', 'correlated_with_input_size', 'boolean', 'static_counter', 'dynamic_counter',
                          'input_size_counter', 'enum', 'enum_value_from_input', 'related']:
                if len(function_variables[label]) > 0:
                    print("")
                    print("  {description}:".format(description=labels_to_description[label]))

                    if label != "related":
                        for variable in function_variables[label]:
                            print("    {fqn}{f}".format(fqn=variable['fqn'], f=features_string(variable)))
                    else:
                        for related in function_variables[label]:
                            print("    {related}".format(related=sorted([variable['fqn'] for variable in related])))

            all_classified_variables += [
                {'class': v['class'], 'fqn': v['fqn'], 'features': v['features']}
                for v in function_variables['variables'] if v['class'] != 'zero_traces'
            ]

    graph.graph_classes(
        base_graphs_path,
        all_classified_variables,
        ["static_counter", "dynamic_counter", "input_size_counter", "enum", "enum_value_from_input"]
    )

    duration = datetime.now() - start_time
    seconds = duration.total_seconds()
    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    seconds = int(seconds % 60)

    print(f"Finished in {hours} hours, {minutes} minutes, and {seconds} seconds")


def classify_variable(variable):
    features = feature_extractor.extract_features(variable)

    if features['num_traces'] < 1:
        return features, "zero_traces"

    if classifiers.is_constant(features):
        return features, "constant"
    elif classifiers.is_boolean(features):
        return features, "boolean"
    elif classifiers.is_counter(features):
        # Some counters with varying deltas may actually be enums, so let's check for that. But some legitimate
        # counters with varying deltas could end up being mis-classified as enums (the classification boundary
        # between counters and enums is kind of fuzzy if you think about it). So let's only try and classify
        # something with varying deltas as an enum if its loop sequence proportion and lag-one autocorrelation on
        # filtered traces is less than 0.9. Filtered traces are those where repeated runs of values are removed, and
        # the correlation metric is actually the average of the lag-one autocorrelations of all identified counter
        # segments with length greater than 2, over all traces. When classifying enums we handle two cases: where
        # the enum value does not derive from the input value, and the case where it does. The former involves
        # situations where the entire set of enum values is probably being iterated over. In the latter case the
        # enum value directly or indirectly derives from some input value.
        if features['varying_deltas'] \
            and features['loop_sequence_proportion'] < 0.9 \
            and features['lag_one_autocorr_filtered'] < 1 \
                and classifiers.is_enum(features):

            if classifiers.is_enum_deriving_values_from_input(features):
                return features, "enum_value_from_input"
            else:
                return features, "enum"
        else:
            counter_class = classifiers.classify_counter(features)
            return features, counter_class + "_counter"

    elif classifiers.is_enum(features):
        if classifiers.is_enum_deriving_values_from_input(features):
            return features, "enum_value_from_input"
        else:
            return features, "enum"

    elif classifiers.is_correlated_with_input_size(features):
        return features, "correlated_with_input_size"

    return features, "unknown"


def identify_related_variables(filename, function, variables_by_filename_and_function):
    print(f"  Identifying related variables in {filename}::{function}")

    related_variables = []
    variables = variables_by_filename_and_function[filename][function]['variables']

    variables_by_fqn = {}
    variables_by_modified_line = {}

    for variable in variables:
        variables_by_fqn[variable['fqn']] = variable

        for modified_line in variable['traces_info']['modified_lines']:
            if modified_line not in variables_by_modified_line:
                variables_by_modified_line[modified_line] = []

            variables_by_modified_line[modified_line].append(variable)

    variable_to_related_variables = {}
    for variable in variables:

        # If the variable has zero traces or is a constant or boolean, ignore it.
        if variable['class'] == 'zero_traces' or variable['class'] == 'constant' or variable['class'] == 'boolean':
            continue

        variable_features = variable['features']

        # print("      Looking for variables related to {fqn}".format(fqn=variable['fqn']))

        # The idea is that related variables will all be modified close to each other, if they are at all. Meaning that
        # if a variable is modified on multiple lines, those variables that are related to it will also be modified the
        # same number of times, close to the original variable. This means that we don't have to scan for related
        # variables at every location that the variable is modified. We can just pick one location and then scan for
        # other variables that are modified within five lines before and after this variable. Note that the variables
        # identified here may not necessarily be related even though they are modified close by. We need to perform some
        # additional checks to make sure they actually are related.

        modified_line = list(variable['traces_info']['modified_lines'])[0]
        candidate_vars = set()
        for delta in range(1, 6):
            for line in [modified_line - delta, modified_line + delta]:
                if line in variables_by_modified_line:
                    vars_modified_on_line = set([
                        var['fqn'] for var in variables_by_modified_line[line] if var['class'] != 'constant'
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
                candidate_features = candidate_var['features']

                if variable_features['num_traces'] == candidate_features['num_traces'] and \
                    variable_features['num_modified_lines'] == candidate_features['num_modified_lines'] and \
                    variable_features['times_modified_max'] == candidate_features['times_modified_max'] and \
                    variable_features['times_modified_min'] == candidate_features['times_modified_min'] and \
                    variable_features['times_modified_mean'] == candidate_features['times_modified_mean'] and \
                        variable_features['times_modified_stddev'] == candidate_features['times_modified_stddev']:

                    if variable['fqn'] not in variable_to_related_variables:
                        variable_to_related_variables[variable['fqn']] = []

                    variable_to_related_variables[variable['fqn']].append(candidate_var_name)
                    # print("        {fqn} is related.".format(fqn=candidate_var_name))

    # We assume that the "related to" relationship is transitive. Meaning that if a is related to b and b is related to
    # c, then a is related to c. So the full set of variables related to a is {b, c}. The following loop basically
    # traverses the "relationship graph" so that we can get the complete set of related variables. The reason that we
    # have to do this is because we only scan for a fixed number of lines before and after a variable's modified line to
    # identify potentially related variables. So while b may be modified within [-5, +5] with respect to a, c may not
    # be. However c could be modified within [-5, +5] with respect to b.
    visited = set()
    for related_var_name in variable_to_related_variables.keys():
        if related_var_name in visited:
            continue

        related = set()
        frontier = {related_var_name}
        while len(frontier) > 0:
            var_name = frontier.pop()
            visited.add(var_name)
            related.add(var_name)

            if var_name in variable_to_related_variables:
                frontier = frontier.union(set(
                    [v for v in variable_to_related_variables[var_name] if v not in visited]
                ))

        related_variables.append([variables_by_fqn[fqn] for fqn in related])

    return related_variables


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Syntax: {script} <experiment> <subject> <binary> <execution>".format(script=sys.argv[0]))
    else:
        main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
