import sys
import os
import gc
import threading
import warnings
import concurrent.futures
import yaml
import bz2
import random
import hashlib
import redis
import pickle
import _pickle as c_pickle

from time import sleep
from datetime import datetime
from itertools import combinations
from functools import partial
from cassandra.auth import PlainTextAuthProvider
from cassandra.cluster import Cluster

from db import cassandra_trace_db, redis_trace_db
from ml import feature_extractor, classifiers
from graphs import graph

#warnings.filterwarnings('error')

BASE_PATH = "/home/vivin/Projects/phd"
BASE_WORKSPACE_PATH = f"{BASE_PATH}/workspace"


def features_string(var):
    features = var['features']

    features_str = " (varying deltas)" if features['varying_deltas'] else ""
    features_str += "\n          num_traces=" + str(features['num_traces'])
    features_str += "\n          num_unique_values=" + str(features['num_unique_values'])
    features_str += "\n          average_value_set_cardinality_ratio="\
                    + str(features['average_value_set_cardinality_ratio'])
    features_str += "\n          loop_sequence_proportion=" + str(features['loop_sequence_proportion'])
    features_str += "\n          directional_consistency=" + str(features['directional_consistency'])
    features_str += "\n          max_values_variance=" + str(features['max_values_variance'])
    features_str += "\n          max_value_to_input_size_correlation="\
                    + str(features['max_value_to_input_size_correlation'])
    features_str += "\n          num_modified_lines=" + str(features['num_modified_lines'])
    features_str += "\n          num_unique_values=" + str(features['num_unique_values'])
    features_str += "\n          times_modified_to_input_size_correlation="\
                    + str(features['times_modified_to_input_size_correlation'])
    features_str += "\n"

    return features_str


def main(experiment: str, subject: str, binary: str, execution: str, action: str):
    print("Experiment: {experiment}".format(experiment=experiment))
    print("Subject:    {subject}".format(subject=subject))
    print("Binary:     {binary}".format(binary=binary))
    print("Execution:  {execution}\n".format(execution=execution))

    base_results_path = f"{BASE_WORKSPACE_PATH}/{experiment}/{subject}/results"
    results_path = f"{base_results_path}/{execution}"
    if not os.path.isdir(results_path):
        raise Exception(f"Could not find results directory at {results_path}")

    graphs_path = f"{results_path}/graphs"
    if not os.path.isdir(graphs_path):
        os.makedirs(graphs_path)

    analysis_data_path = f"{results_path}/analysis_data"
    if not os.path.isdir(analysis_data_path):
        os.makedirs(analysis_data_path)

    if action == "graph_from_saved":
        print("Plotting graphs using saved classified variables...")
        print("")
        classified_variables = load_classified_variables(analysis_data_path, "classified_variables_to_graph")
        plot_variable_classes(
            graphs_path,
            classified_variables,
            [
                "static_counter",
                "dynamic_counter",
                "input_size_counter",
                "enum_from_input"
            ]
        )
    elif action == "identify_interesting_from_saved":
        print("Identifying interesting variables using saved classified variables...")
        print("")

        variables_by_filename_and_function = load_classification_results(analysis_data_path, "classification_results")
        print_classification_results(variables_by_filename_and_function)
        print("")

        # We don't need to instrument every single classified variable. Some aren't interesting and there can also
        # be duplicates. So we will only target the interesting ones for instrumentation.
        interesting_variables = identify_interesting_variables(variables_by_filename_and_function)
        with open(f"{base_results_path}/sandpuppy_interesting_variables.yml", "w") as f:
            yaml.dump(interesting_variables, f, default_flow_style=False, indent=2)
    elif action == "random_variable_instrumentation":
        print("Identifying random set of variables to instrument...")
        print("")

        variables_by_filename_and_function = load_classification_results(analysis_data_path, "classification_results")
        random_variables = random_variable_instrumentation(variables_by_filename_and_function)
        with open(f"{base_results_path}/sandpuppy_interesting_variables_random.yml", "w") as f:
            yaml.dump(random_variables, f, default_flow_style=False, indent=2)
    else:
        start_time = datetime.now()

        variables_by_filename_and_function = classify_variables(experiment, subject, binary, execution, action)
        print_classification_results(variables_by_filename_and_function)
        print("")

        save_classification_results(analysis_data_path, "classification_results", variables_by_filename_and_function)

        # We don't need to instrument every single classified variable. Some aren't interesting and there can also
        # be duplicates. So we will only target the interesting ones for instrumentation.
        interesting_variables = identify_interesting_variables(variables_by_filename_and_function)
        with open(f"{base_results_path}/sandpuppy_interesting_variables.yml", "w") as f:
            yaml.dump(interesting_variables, f, default_flow_style=False, indent=2)

        # Let's plot some graphs for these classified variables
        classified_variables_to_graph = []
        for filename in sorted(variables_by_filename_and_function.keys()):
            for function in sorted(variables_by_filename_and_function[filename].keys()):
                function_variables = variables_by_filename_and_function[filename][function]
                classified_variables_to_graph += [
                    {'class': v['class'], 'fqn': v['fqn'], 'features': v['features']}
                    for v in function_variables['variables'] if v['class'] != 'zero_traces'
                ]

        save_classified_variables(analysis_data_path, "classified_variables_to_graph", classified_variables_to_graph)

        print("")

        plot_variable_classes(
            graphs_path,
            classified_variables_to_graph,
            [
                "static_counter",
                "dynamic_counter",
                "input_size_counter",
                "enum_from_input"
            ]
        )

        duration = datetime.now() - start_time
        seconds = duration.total_seconds()
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        seconds = int(seconds % 60)

        print(f"Finished in {hours} hours, {minutes} minutes, and {seconds} seconds")


def connect_to_redis():
    return redis.Redis(host='localhost', port=6379, db=0)


def connect_to_cassandra():
    auth_provider = PlainTextAuthProvider(username='phd', password='phd')
    cluster = Cluster(protocol_version=4, auth_provider=auth_provider)
    session = cluster.connect('phd')
    session.default_timeout = 60

    return session


def random_variable_instrumentation(variables_by_filename_and_function):
    retrieved_variables = []
    for filename in variables_by_filename_and_function:
        for function in variables_by_filename_and_function[filename]:
            retrieved_variables += variables_by_filename_and_function[filename][function]['variables']

    random.shuffle(retrieved_variables)

    interesting_variables = {
        'max': [],
        'perm': [],
        'hash': [],
        'max2': []
    }

    # 10 random variables for vvmax
    for variable in random.sample(retrieved_variables, 10):
        filename = variable['filename']
        function = variable['function']
        interesting_variables['max'].append(f"{filename}:{function}:{variable['name']}:{variable['declared_line']}")

    # 10 random variables for vvperm
    for variable in random.sample(retrieved_variables, 10):
        filename = variable['filename']
        function = variable['function']
        interesting_variables['perm'].append({
            'variable': f"{filename}:{function}:{variable['name']}:{variable['declared_line']}",
            'max': variable['features']['most_max_value'],
            'min': variable['features']['most_min_value']
        })

    # 5 random pairs for hash and max2
    num_pairs_identified = 0
    while num_pairs_identified < 5:
        filename = random.sample(variables_by_filename_and_function.keys(), 1)[0]
        function = random.sample(variables_by_filename_and_function[filename].keys(), 1)[0]

        # Function needs to have at least two variables
        if len(variables_by_filename_and_function[filename][function]['variables']) < 2:
            continue

        pair = random.sample(variables_by_filename_and_function[filename][function]['variables'], 2)

        first_variable = f"{filename}:{function}:{pair[0]['name']}:{pair[0]['declared_line']}"
        first_min = pair[0]['features']['most_min_value']
        first_max = pair[0]['features']['most_max_value']

        second_variable = f"{filename}:{function}:{pair[1]['name']}:{pair[1]['declared_line']}"
        second_min = pair[1]['features']['most_min_value']
        second_max = pair[1]['features']['most_max_value']

        # We may end up with constants, but we don't care because this is a random sampling. Since the orchestrator
        # tries to be smart about it as far as generating targets based on the max, min and slot sizes, let us make
        # sure it does not ignore situations where we have constants.
        if first_min == first_max:
            first_max = first_min + 1
        if second_min == second_max:
            second_max = second_min + 1

        interesting_variables['hash'].append([first_variable, second_variable])

        # Two entries per pair: maximize variable 1 with respect to variable 2 and
        # variable 2 with respect to variable 1.
        interesting_variables['max2'] += [{
            'first_variable': first_variable,
            'second_variable': second_variable,
            'second_min': second_min,
            'second_max': second_max
        }, {
            'first_variable': second_variable,
            'second_variable': first_variable,
            'second_min': first_min,
            'second_max': first_max
        }]

        num_pairs_identified += 1

    return interesting_variables


def classify_variables(experiment: str, subject: str, binary: str, execution: str, action: str):
    base_results_path = f"{BASE_WORKSPACE_PATH}/{experiment}/{subject}/results"
    results_path = f"{base_results_path}/{execution}"
    analysis_data_path = f"{results_path}/analysis_data"

    client = connect_to_redis()

    print("Identifying files, functions, and variables...")
    retrieved_variables, variables_by_filename_and_function = retrieve_variables(client, subject)

    num_retrieved_variables = len(retrieved_variables)
    if action == "classify_from_saved":
        print(f"Loading saved traces for {num_retrieved_variables} variables and classifying...")
    else:
        print(f"Retrieving traces for {num_retrieved_variables} variables and classifying...")

    done = threading.Event()
    with concurrent.futures.ThreadPoolExecutor(max_workers=512) as thread_pool_executor,\
         concurrent.futures.ProcessPoolExecutor(max_workers=12) as process_pool_executor:

        counts = {'processed': 0}
        
        def retrieve_traces_callback(future, _variable):
            _variable['traces_info'] = future.result()
            del future

            # Save the traces to disk and delete them from memory. We will load them only when we need to classify
            # them.
            save_variable_traces_info(analysis_data_path, _variable)
            del _variable['traces_info']
            gc.collect()

            process_pool_executor.submit(
                classify_variable_using_saved_traces,
                path=analysis_data_path,
                variable=_variable
            ).add_done_callback(partial(classify_callback, _variable=_variable))

        def classify_callback(future, _variable):

            # Need to return this from classify method because the variable in the parent process does not have
            # traces_info, and therefore no modified_lines. It's ok to return it since it's pretty small and we
            # do need it to identify related variables later on.
            features, variable_class, modified_lines = future.result()
            _variable['features'] = features
            _variable['class'] = variable_class
            _variable['traces_info'] = {
                'modified_lines': modified_lines
            }

            _filename = _variable['filename']
            _function = _variable['function']
            variables_by_filename_and_function[_filename][_function][variable_class].append(_variable)

            # Delete the future to free up memory
            del future

            counts['processed'] += 1
            if counts['processed'] % 10 != 0 and counts['processed'] % 5 != 0:
                print(".", end='', flush=True)
                gc.collect()
            elif counts['processed'] % 10 == 0:
                print(counts['processed'], end='', flush=True)
            elif counts['processed'] % 5 == 0:
                print("o", end='', flush=True)

            if counts['processed'] == num_retrieved_variables:
                done.set()

        for variable in retrieved_variables:
            # If we are classifying from saved traces, go ahead and just use the process pool executor to do that.
            # Otherwise, use the thread pool executor to retrieve the traces from the database. The callback will
            # save the traces to disk, delete them from memory, and then submit a task to the process pool executor
            # to classify from saved traces.
            if action == "classify_from_saved":
                process_pool_executor.submit(
                    classify_variable_using_saved_traces,
                    path=analysis_data_path,
                    variable=variable
                ).add_done_callback(partial(classify_callback, _variable=variable))
            else:
                thread_pool_executor.submit(
                    redis_trace_db.retrieve_variable_value_traces_information,
                    variable=variable,
                    client=client,
                    experiment=experiment,
                    subject=subject,
                    binary=binary,
                    execution=execution,
                    exit_status='success',
                    filename=variable['filename'],
                    function=variable['function']
                ).add_done_callback(partial(retrieve_traces_callback, _variable=variable))

        thread_pool_executor.shutdown(wait=False)

        done.wait()
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

    return variables_by_filename_and_function


def retrieve_variables(session, subject):
    variables_by_filename_and_function = {}
    retrieved_variables = []

    filenames = redis_trace_db.get_subject_filenames(session, subject)
    for filename in sorted(filenames):
        variables_by_filename_and_function[filename] = {}

        functions = redis_trace_db.get_subject_file_functions(session, subject, filename)
        for function in sorted(functions):
            variables = redis_trace_db.get_subject_file_function_variables_of_type(session, subject, filename,
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
                'enum_from_input': [],
                'unknown': [],
                'related': []
            }

            retrieved_variables += variables

    return retrieved_variables, variables_by_filename_and_function


def print_classification_results(variables_by_filename_and_function):
    labels_to_description = {
        'constant': "Constants",
        'correlated_with_input_size': "Variables correlated with input size",
        'boolean': "Booleans",
        'static_counter': "Static Counters",
        'dynamic_counter': "Dynamic Counters",
        'input_size_counter': "Counters correlated with input size",
        'enum_from_input': "Enums deriving value from input",
        'related': "Related variables"
    }
    for filename in sorted(variables_by_filename_and_function.keys()):
        for function in sorted(variables_by_filename_and_function[filename].keys()):
            function_variables = variables_by_filename_and_function[filename][function]
            for variable in sorted(function_variables['variables'], key=lambda d: d['name']):
                print(f"#VAR#: {variable['class']} {variable['fqn']}")

    print("")
    for filename in sorted(variables_by_filename_and_function.keys()):
        for function in sorted(variables_by_filename_and_function[filename].keys()):
            function_variables = variables_by_filename_and_function[filename][function]

            for label in ['constant', 'correlated_with_input_size', 'boolean', 'static_counter', 'dynamic_counter',
                          'input_size_counter', 'enum_from_input', 'related']:
                if len(function_variables[label]) > 0:

                    print("")
                    print("  {description}:".format(description=labels_to_description[label]))

                    if label != "related":
                        function_variables[label].sort(key=lambda var: var['fqn'])
                        for variable in function_variables[label]:
                            print("    {fqn}{f}".format(fqn=variable['fqn'], f=features_string(variable)))
                    else:
                        for related in function_variables[label]:
                            print("    {related}".format(related=sorted([variable['fqn'] for variable in related])))


def identify_interesting_variables(variables_by_filename_and_function):
    interesting_variables = {
        'max': [],
        'perm': [],
        'hash': [],
        'max2': []
    }

    # For instrumentation passes where we are maximizing the values of certain variables, or maximizing permutations of
    # enum variable values, it would be advantageous to exclude duplicates. Duplicates are basically the same variable
    # that happens to show up as a separate one because it has been passed to another function. We can identify
    # duplicates by comparing the features of variables. If any two variables have the same features then they can be
    # considered to be the same variable. The instrumented set will keep track of variables we have already considered
    # for instrumentation.
    instrumented = set()

    for filename in sorted(variables_by_filename_and_function.keys()):
        for function in sorted(variables_by_filename_and_function[filename].keys()):
            function_variables = variables_by_filename_and_function[filename][function]

            for label in ['constant', 'correlated_with_input_size', 'boolean', 'static_counter', 'dynamic_counter',
                          'input_size_counter', 'enum_from_input', 'related']:
                if len(function_variables[label]) > 0:

                    if label in ['correlated_with_input_size', 'dynamic_counter', 'input_size_counter']:
                        interesting_variables['max'] += [
                            f"{filename}:{function}:{variable['name']}:{variable['declared_line']}"
                            for variable in function_variables[label]
                            if features_string(variable) not in instrumented and
                            ((label != 'correlated_with_input_size' and
                              variable['features']['average_counter_segment_length_filtered'] > 4) or
                             (label == 'correlated_with_input_size' and
                              variable['features']['num_unique_values'] > 9))
                        ]

                        for variable in function_variables[label]:
                            instrumented.add(features_string(variable))

                    if label == "enum_from_input":
                        for variable in function_variables[label]:

                            variable_entry = f"{filename}:{function}:{variable['name']}:{variable['declared_line']}"
                            if features_string(variable) not in instrumented \
                               and variable['features']['num_unique_values'] > 4:
                                interesting_variables['perm'].append({
                                    'variable': variable_entry,
                                    'max': variable['features']['most_max_value'],
                                    'min': variable['features']['most_min_value']
                                })

                                instrumented.add(features_string(variable))

                    if label == "related":
                        for related in function_variables[label]:
                            for pair in combinations(related, 2):
                                # num_value_combinations = pair[0]['features']['num_unique_values'] * \
                                #                          pair[1]['features']['num_unique_values']

                                first_variable = f"{filename}:{function}:{pair[0]['name']}:{pair[0]['declared_line']}"
                                first_min = pair[0]['features']['most_min_value']
                                first_max = pair[0]['features']['most_max_value']

                                second_variable = f"{filename}:{function}:{pair[1]['name']}:{pair[1]['declared_line']}"
                                second_min = pair[1]['features']['most_min_value']
                                second_max = pair[1]['features']['most_max_value']

                                interesting_variables['hash'].append([first_variable, second_variable])

                                # Two entries per pair: maximize variable 1 with respect to variable 2 and
                                # variable 2 with respect to variable 1.
                                interesting_variables['max2'] += [{
                                    'first_variable': first_variable,
                                    'second_variable': second_variable,
                                    'second_min': second_min,
                                    'second_max': second_max
                                }, {
                                    'first_variable': second_variable,
                                    'second_variable': first_variable,
                                    'second_min': first_min,
                                    'second_max': first_max
                                }]

    return interesting_variables


def load_classification_results(path, filename):
    classification_results_file = f"{path}/{filename}.pbz2"
    if not os.path.isfile(classification_results_file):
        raise Exception(f"Could not find classification results file at {classification_results_file}")

    classification_results = bz2.BZ2File(classification_results_file, "rb")
    classification_results = c_pickle.load(classification_results)
    return classification_results


def save_classification_results(path, filename, classification_results):
    classification_results_file = f"{path}/{filename}.pbz2"
    with bz2.BZ2File(classification_results_file, "w") as f:
        c_pickle.dump(classification_results, f)

    print(f"Saved classification results to {classification_results_file}")


def load_classified_variables(path, filename):
    classified_variables_file = f"{path}/{filename}.pbz2"
    if not os.path.isfile(classified_variables_file):
        raise Exception(f"Could not find classified variables file at {classified_variables_file}")

    variables = bz2.BZ2File(classified_variables_file, "rb")
    variables = c_pickle.load(variables)
    return variables


def save_classified_variables(path, filename, variables):
    classified_variables_file = f"{path}/{filename}.pbz2"
    with bz2.BZ2File(classified_variables_file, "w") as f:
        c_pickle.dump(variables, f)

    print(f"Saved classified variables to {classified_variables_file}")


def load_variable_traces_info(path, variable):
    fqn = variable['fqn']
    fqn_hash = hashlib.sha256(fqn.encode()).hexdigest()
    variable_traces_info_file = f"{path}/{fqn_hash}.traces_info.pbz2"
    if not os.path.isfile(variable_traces_info_file):
        raise Exception(f"Could not find variable traces info file at {variable_traces_info_file}")

    traces_info = bz2.BZ2File(variable_traces_info_file, "rb")
    traces_info = c_pickle.load(traces_info)
    return traces_info


def save_variable_traces_info(path, variable):
    fqn = variable['fqn']
    fqn_hash = hashlib.sha256(fqn.encode()).hexdigest()
    traces_info = variable['traces_info']
    variable_traces_info_file = f"{path}/{fqn_hash}.traces_info.pbz2"
    with bz2.BZ2File(variable_traces_info_file, "w") as f:
        c_pickle.dump(traces_info, f)


def plot_variable_classes(path, variables, classes):
    graph.graph_classes(path, variables, classes)


def classify_variable_using_saved_traces(path, variable):
    variable['traces_info'] = load_variable_traces_info(path, variable)
    return classify_variable(variable)


def classify_variable(variable):
    features = feature_extractor.extract_features(variable)

    if features['num_traces'] < 1:
        return features, "zero_traces", variable['traces_info']['modified_lines']

    if classifiers.is_constant(features):
        return features, "constant", variable['traces_info']['modified_lines']
    elif classifiers.is_boolean(features):
        return features, "boolean", variable['traces_info']['modified_lines']
    elif classifiers.is_counter(features):
        counter_class = classifiers.classify_counter(features)
        return features, counter_class + "_counter", variable['traces_info']['modified_lines']

    elif classifiers.is_enum(features):
        return features, "enum_from_input", variable['traces_info']['modified_lines']

    elif classifiers.is_correlated_with_input_size(features):
        return features, "correlated_with_input_size", variable['traces_info']['modified_lines']

    return features, "unknown", variable['traces_info']['modified_lines']


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
        delta = 6
        for line in [modified_line - delta, modified_line + delta]:
            if line in variables_by_modified_line:
                vars_modified_on_line = set([
                    var['fqn'] for var in variables_by_modified_line[line]
                    if var['class'] != 'constant' and var['class'] != 'boolean'
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
    if len(sys.argv) < 5:
        print("Syntax: {script} <experiment> <subject> <binary> <execution> "
              "[(classify|graph|identify_interesting)_from_saved]".format(script=sys.argv[0]))
    else:
        if len(sys.argv) < 6:
            action = None
        else:
            action = sys.argv[5]

        main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], action)
