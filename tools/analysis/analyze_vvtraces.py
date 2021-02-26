import sys
import re
import numpy
import pandas

from cassandra.cluster import Cluster
from sparklines import sparklines

from sklearn.preprocessing import minmax_scale
#from tslearn.clustering import TimeSeriesKMeans

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

            if len(classified_variables['correlated_with_input_size']) > 0:
                print("")
                print("    Variables correlated with input size:")
                for variable in classified_variables['correlated_with_input_size']:
                    print("      {fqn}".format(fqn=variable['fqn']))

            if len(classified_variables['static_counters']) > 0:
                print("")
                print("    Static Counters:")
                for variable in classified_variables['static_counters']:
                    print("      {fqn}{varying} {prop}".format(
                        fqn=variable['fqn'],
                        varying=" (varying deltas)" if variable['info']['varying_deltas'] else "",
                        prop=variable['info']['loop_sequence_proportion']
                    ))

            if len(classified_variables['dynamic_counters']) > 0:
                print("")
                print("    Dynamic Counters:")
                for variable in classified_variables['dynamic_counters']:
                    print("      {fqn}{varying} {prop}".format(
                        fqn=variable['fqn'],
                        varying=" (varying deltas)" if variable['info']['varying_deltas'] else "",
                        prop=variable['info']['loop_sequence_proportion']
                    ))

            if len(classified_variables['input_size_counters']) > 0:
                print("")
                print("    Counters correlated with input size:")
                for variable in classified_variables['input_size_counters']:
                    print("      {fqn}{varying} {prop}".format(
                        fqn=variable['fqn'],
                        varying=" (varying deltas)" if variable['info']['varying_deltas'] else "",
                        prop=variable['info']['loop_sequence_proportion']
                    ))

            if len(classified_variables['enums']) > 0:
                print("")
                print("    Enums:")
                for variable in classified_variables['enums']:
                    print("      {fqn} {prop}".format(fqn=variable['fqn'], prop=variable['info']['loop_sequence_proportion']))

            if len(classified_variables['related']) > 0:
                print("")
                print("    Related variables:")
                for related in classified_variables['related']:
                    print("      {related}".format(related=sorted([variable['fqn'] for variable in related])))

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
    # TODO: other things you can do: compare trace of variable with trace of another variable. see if one is proper
    # TODO: subset maybe? compare timestampts too?


def classify_variables(variables):

    def is_constant(var):
        # Pretty simple. If the variable is only modified at one place and only has one unique value, it is a constant.
        return var['analysis']['num_modified_lines'] == 1 and var['analysis']['num_unique_values'] == 1

    # TODO: test for correlation of variables with input size and counters with input size needs to be stricter. make
    # TODO: threshold higher?
    def is_correlated_with_input_size(var):
        # We are looking for variables whose values may reflect some correlation with the input size. Essentially we
        # are looking for "size" or "length" type variables. We only focus on the maximum value (per trace) and only
        # for those traces that contain either 1 or 2 elements. This is because these variables are either initialized
        # to a value and then left unchanged, or are initialized to zero and then set to to a value and left unchanged.
        # Note that "count" type variables that count up to a value correlated with input size are handled separately.
        input_sizes = []
        max_values = []
        for trace in var['info']['traces']:
            if 0 < len(trace['items']) < 3:
                max_values.append(max([int(item['variable_value']) for item in trace['items']]))
                input_sizes.append(trace['input_size'])

        if len(input_sizes) == 0 or len(max_values) == 0:
            return False

        input_sizes_variance = numpy.var(input_sizes)
        max_values_variance = numpy.var(max_values)

        if input_sizes_variance == 0 or max_values_variance == 0:
            return False

        r = numpy.corrcoef(input_sizes, max_values)
        if r[0, 1] >= 0.5 and r[1, 0] >= 0.5:
            return True

        return False

    def is_counter(var):

        # First we are going to filter out and clean up traces. We ignore any trace with less than two items. Then we
        # will clean up "runs" of values in a trace. Runs of values can happen normally for non-counter variables. But
        # it is possible with counters well if the loop never gets started because the counter variable is initialized
        # to a value that already satisfies the end condition of the loop. By replacing these runs with just a single
        # instance of the repeated value, it is much easier to identify potential loop sequences. We do not have to
        # worry about mis-classifying non-counter variables as counters if they happen have series of values that
        # translate to a valid loop sequence, because we will also calculate the proportion of such values with respect
        # to the total number of values. If this proportion is less than 0.5, we will not consider the variable as a
        # counter. Since in general, counter variables will have a higher proportion of values (if not all) that are
        # part of a loop sequence, this can help us weed out false positives.
        traces = []
        for trace in var['info']['traces']:
            if len(trace['items']) < 2:
                continue

            new_trace = []
            previous_value = None
            for item in trace['items']:
                current_value = int(item['variable_value'])
                if current_value != previous_value:
                    new_trace.append(current_value)
                    previous_value = current_value

            if len(new_trace) > 1:
                traces.append(new_trace)

        # The total length of all traces
        trace_lengths_sum = sum(var['analysis']['times_modified'])

        # The sum of the lengths of all identified loop sequences across all traces. This is the same as the number of
        # trace elements (basically variable values) across all traces that are part of a loop sequence.
        loop_sequence_lengths_sum = 0

        # Keep track of the number of iterations this variable goes through, each time it goes through a loop. Basically
        # this is the number of times a variable is incremented/decremented until it reaches its limit. We do this so
        # that we can exclude those variables that appear to go through only one iteration. This typically happens in
        # the case of boolean-like variables that flip between 0 and 1, or in general, variables that flip between two
        # fixed values.
        combined_iterations = []

        # Keep track of the deltas between successive values within a single loop sequence.
        deltas = []

        # Keep track of the deltas between successive values from all identified loop sequences. The reason we maintain
        # these deltas is to exclude variables that may increase (or decrease) but at very high rates. Currently we
        # exclude any variable that has a mean delta (across all traces) greater than 255.
        combined_deltas = []

        # Now we process our subset of cleaned up traces. The intent is to identify sequences of increasing and
        # decreasing values. There may be multiple such sequences per trace. Based on certain aggregate features of
        # these sequences, we can determine whether the variable might be a counter.
        #
        # The
        # individual feature that we keep track of is an array of deltas between each successive pair. For a counter
        # this value must be constant, meaning that there should only be one unique delta value. While there can be
        # and are counters that increment with varying deltas per iteration, it is difficult to distinguish them from
        # variables that simply happen to always increase or decrease. # TODO: do we really need to ignore? digestSize
        # TODO: is a static counter because it just goes through digest sizes from 20, 32, 48, to 64. let's try ignoring

        var['info']['varying_deltas'] = False
        var['info']['loop_sequence_proportion'] = 0
        counter = True
        for trace in traces:

            # The direction of the loop. Tells us if the loop is incrementing or decrementing. Given a sequence of
            # values that could be part of a loop, we establish the loop direction based on the relationship between
            # the first two values in the sequence: (t[1] - t[0]) / abs(t[1] - t[0]). As long as successive values
            # have the same relation (i.e., the values are "moving" in the same direction) they will be considered
            # part of a loop sequence. If any pair of successive values don't have the same relationship, it might
            # mean that the loop has ended. This variable helps handle the case where there are multiple potential
            # loop sequences in a single trace.
            loop_direction = None

            index = 0
            while index < len(trace) - 1 and counter:
                current_value = trace[index]
                next_value = trace[index + 1]

                delta = next_value - current_value

                # If loop_direction is None, we are at the beginning of a new loop. This happens right at the start of
                # the trace but can also happen anywhere in the middle. For example [0, 1, 2, 3, 4, 0, 1, 2, 3, 5] has
                # a new loop starting at position 5. We detect this case and reset loop_direction to None so that we can
                # establish a new loop direction using the first two values of the new sequence.
                if loop_direction is None:
                    loop_direction = delta / abs(delta)

                # Calculate the current direction based on the sign of val[t + 1] - val[t]
                current_direction = delta / abs(delta)

                if current_direction == loop_direction:
                    # If the direction is the same as the loop direction (i.e, we continue to increment/decrement) add
                    # the delta to our list of deltas for this loop, and to the list of combined deltas as well.
                    deltas.append(abs(delta))
                    combined_deltas.append(abs(delta))
                else:
                    # If the current direction is different from the loop direction, the loop might have ended.
                    if len(set(deltas)) > 1:
                        var['info']['varying_deltas'] = True

                    combined_iterations.append(len(deltas))
                    loop_sequence_lengths_sum += len(deltas) + 1
                    deltas = []
                    loop_direction = None

                index += 1

        # If the entire trace is a loop sequence, or there is a loop sequence that starts somewhere in the middle of
        # the trace and runs till the end, we will have exited the loop without saving the deltas. If this happens
        # the deltas list will contain elements, so we can handle that case here.
        if len(deltas) > 0:
            if len(set(deltas)) > 1:
                var['info']['varying_deltas'] = True

            combined_iterations.append(len(deltas))
            loop_sequence_lengths_sum += len(deltas) + 1

        loop_sequence_proportion = (loop_sequence_lengths_sum / trace_lengths_sum)
        var['info']['loop_sequence_proportion'] = loop_sequence_proportion
        # print("      ", "counter =", counter, " len(combined_deltas) =", len(combined_deltas),
        #      " mean combined deltas =", numpy.mean(combined_deltas) if len(combined_deltas) > 0 else 0,
        #      " len(combined_iterations) =", len(combined_iterations),
        #      " max combined iterations =", max(combined_iterations) if len(combined_iterations) > 0 else 0,
        #      " proportion_part of loop =", loop_sequence_proportion, "\n")
        # The check for <= 255 is to ignore things that have huge jumps in value
        return counter and len(combined_deltas) > 0 and numpy.mean(combined_deltas) <= 255 \
            and loop_sequence_proportion > 0.5

    def classify_counter(var):
        # We know it is a counter. But is it a static counter or a dynamic one? Meaning, does it always count
        # up to a fixed value, or does it vary? To find out let's look at the maximum values in the traces.

        input_sizes = []
        counter_max_values = []
        for trace in var['info']['traces']:
            if len(trace['items']) > 1:
                input_sizes.append(trace['input_size'])
                counter_max_values.append(max([int(item['variable_value']) for item in trace['items']]))

        input_sizes_variance = numpy.var(input_sizes)
        counter_max_values_variance = numpy.var(counter_max_values)

        # If the counter maximum values are all the same this is a static counter. If the counter maximum values are
        # different but the input sizes are the same, it suggests that the counter is not affected by the input size
        # but counts up to different values, which makes it a dynamic counter.
        #
        # TODO: check if it counts up to the same set of values every time. this also makes it static. Maybe call it
        # TODO: multiple_static.
        #
        # If neither of the variances are zero, then we can see if the maximum values of the counter are correlated with
        # input size. If that is the case this makes it an input-size counter. Otherwise it is a dynamic counter.
        if counter_max_values_variance == 0:
            return "static"
        elif input_sizes_variance == 0:
            return "dynamic"

        r = numpy.corrcoef(input_sizes, counter_max_values)
        if r[0, 1] < 0.5 or r[1, 0] < 0.5:
            return "dynamic"
        else:
            return "input_size"

    def is_enum(var):
        # Looking for enum-like variables. We are already looking for variables that have been modified more than
        # once. Since we are looking to maximize the combinations in the input, what can we tell about the var?
        # Let's maybe first see if there is a correlation between the number of times it is invoked and the input
        # size? So our data set we will collect will be two arrays. The array will have an entry per process trace.
        # First array will hold number of times a variable was modified. Second will hold the size of the input for
        # that process.

        times_modified = var['analysis']['times_modified']
        times_modified_variance = var['analysis']['times_modified_variance']

        input_sizes = var['analysis']['input_sizes']
        input_sizes_variance = var['analysis']['input_sizes_variance']

        # if "ExecCommand" in variable['fqn']:
        #    print("times_modified", times_modified)
        #    print("input_sizes", input_sizes)

        # TODO: counters that flip between just two values end up being misclassified as enums. Need to handle that.
        # TODO: also need to add a test that checks to see if the variable goes through the exact same set of values
        # TODO: in every trace. if that is the case it might not be an enum variable.

        if times_modified_variance == 0 or input_sizes_variance == 0:
            return False

        r = numpy.corrcoef(times_modified, input_sizes)

        # print("      Number of times {fqn} is modified is correlated with input size "
        #      "(Pearson coefficients are {a} and {b}).".format(fqn=variable['fqn'], a=r[0, 1], b=r[1, 0]))

        # We will look for Pearson coefficients greater than 0.25 to see if the number of times a variable is modified
        # is correlated with input size. Note that one issue is that the input size isn't necessarily the same as the
        # size of the input _actually processed_. The input size we end up reporting from AFL is the size of the input
        # sent to the process and it may fail early due to invalid input. Ideally it would be nice if we were able to
        # ascertain the amount of bytes actually read by the process from either stdin or a file. Not sure if that is
        # possible, though.
        if r[0, 1] < 0.25 or r[1, 0] < 0.25:
            return False

        variable_values = numpy.array(var['info']['variable_values']).astype(numpy.float)
        order_of_magnitudes = [numpy.log10(v) if v > 0 else 0 for v in variable_values]

        # This is super sketch, and I probably need to mathematically prove it or something. But anyway, the
        # assumption is that these enum values come from a small set of values, and even if sequential,
        # aren't wildly different in their magnitudes. We have a limit of 255 unique values and so we don't
        # expect those to vary wildly in an enum. For example, it's not likely we will have an enum with
        # values like 0, 1, 2, and then 12355914 or something. So what we'll do is calculate the standard
        # deviation of the log10 of the values and ignore the variable if that value is greater than 1.
        if numpy.std(order_of_magnitudes) > 1:
            return False

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
        if var['analysis']['num_modified_lines'] == 1 and var['analysis']['num_unique_values'] <= 255:
            # Deal with case 1:
            # For now we will limit ourselves to variables that have up to 255 unique values
            return True
        elif var['analysis']['num_modified_lines'] == var['analysis']['num_unique_values']:
            # Deal with case 2. Basically the number of lines it is modified on should equal the number of
            # unique values it holds
            return True

        return False

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
        analyze_variable(variable)

        if variable['analysis']['num_traces'] < 1:
            print("      Not classifying {fqn} as it has zero traces.".format(fqn=variable['fqn']))
            variable['class'] = "zero_traces"
            continue
        else:
            print("      Attempting to classify {fqn}...".format(fqn=variable['fqn']))

        if is_constant(variable):
            if is_correlated_with_input_size(variable):
                variable['class'] = "correlated_with_input_size"
                classified_vars['correlated_with_input_size'].append(variable)
            else:
                variable['class'] = "constant"
                classified_vars['constants'].append(variable)
        elif is_counter(variable):
            # Some counters with varying deltas may actually be enums, so let's check for that. But some legitimate
            # counters with varying deltas could end up being mis-classified as enums (the classification boundary
            # between counters and enums is kind of fuzzy if you think about it). So let's only try and classify
            # something with varying deltas as an enum if its loop sequence proportion is less than 0.9.
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
            if variable['info']['varying_deltas'] \
                    and variable['info']['loop_sequence_proportion'] < 0.9 \
                    and is_enum(variable):
                variable['class'] = "enum"
                classified_vars['enums'].append(variable)
            else:
                counter_class = classify_counter(variable)
                variable['class'] = counter_class + "_counter"
                classified_vars[counter_class + "_counters"].append(variable)
        elif is_enum(variable):
            variable['class'] = "enum"
            classified_vars['enums'].append(variable)
        elif is_correlated_with_input_size(variable):
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
        # If the variable is already classified, ignore.
        if 'class' in variable and variable['class'] == 'zero_traces':
            continue

        analysis = variable['analysis']

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

            previous_line = modified_line - delta
            if previous_line in variables_by_modified_line:
                modified_vars_previous_line = set(
                    [var['fqn'] for var in variables_by_modified_line[previous_line]]  # TODO: ignore constants
                ).difference([variable['fqn']])
                if len(modified_vars_previous_line) > 0:
                    # print("        Variables modified on previous line {l} ({delta}): {vars}".format(
                    #     l=previous_line, vars=modified_vars_previous_line, delta=delta
                    # ))
                    candidate_vars = candidate_vars.union(modified_vars_previous_line)

            next_line = modified_line + delta
            if next_line in variables_by_modified_line:
                modified_vars_next_line = set(
                    [var['fqn'] for var in variables_by_modified_line[next_line]]  # TODO: ignore constants. check 'class' of var
                ).difference([variable['fqn']])
                if len(modified_vars_next_line) > 0:
                    # print("        Variables modified on next line {l} ({delta}): {vars}".format(
                    #     l=next_line, vars=modified_vars_next_line, delta=delta
                    # ))
                    candidate_vars = candidate_vars.union(modified_vars_next_line)

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
                candidate_var_analysis = candidate_var['analysis']

                if analysis['num_traces'] == candidate_var_analysis['num_traces'] and \
                        analysis['num_modified_lines'] == candidate_var_analysis['num_modified_lines'] and \
                        analysis['times_modified_max'] == candidate_var_analysis['times_modified_max'] and \
                        analysis['times_modified_min'] == candidate_var_analysis['times_modified_min'] and \
                        analysis['times_modified_mean'] == candidate_var_analysis['times_modified_mean'] and \
                        analysis['times_modified_stddev'] == candidate_var_analysis['times_modified_stddev']:

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
            related.add(var_name)
            visited.add(var_name)

            if var_name in related_vars:
                frontier = frontier.union(set(
                    [v for v in related_vars[var_name] if v not in visited]
                ))

        classified_vars['related'].append([variables_by_fqn[fqn] for fqn in related])

    # for related in classified_vars['related']:
        # print("      Related variables: {rel}".format(rel=related))

    return classified_vars


# TODO: how many false negatives do we have??? need to make a test program with all kinds of counters... see
# TODO: which ones aren't picked up

def analyze_variable(variable):
    analysis = dict()

    analysis['num_traces'] = len(variable['info']['traces'])
    analysis['num_modified_lines'] = len(variable['info']['modified_lines'])
    analysis['num_unique_values'] = len(set(variable['info']['variable_values']))

    times_modified = []
    input_sizes = []
    for trace in variable['info']['traces']:
        times_modified.append(len(trace['items']))
        input_sizes.append(trace['input_size'])

    analysis['times_modified'] = times_modified
    analysis['times_modified_variance'] = numpy.var(times_modified) if len(times_modified) > 0 else 0

    analysis['times_modified_min'] = numpy.min(times_modified) if len(times_modified) > 0 else 0
    analysis['times_modified_max'] = numpy.max(times_modified) if len(times_modified) > 0 else 0
    analysis['times_modified_mean'] = numpy.mean(times_modified) if len(times_modified) > 0 else 0
    analysis['times_modified_stddev'] = numpy.std(times_modified) if len(times_modified) > 0 else 0

    analysis['input_sizes'] = input_sizes
    analysis['input_sizes_variance'] = numpy.var(input_sizes) if len(input_sizes) > 0 else 0

    variable['analysis'] = analysis


def print_variables_info(variables):
    for variable in variables:
        print("      {fqn}".format(fqn=variable['fqn']))

        analyze_variable(variable)
        analysis = variable['analysis']

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
            min=analysis['times_modified_min'],
            max=analysis['times_modified_max']
        ))
        print("        Is modified an average of {avg} times per process (standard deviation={stddev})".format(
            avg=analysis['times_modified_mean'],
            stddev=analysis['times_modified_stddev']
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
            'fqn': "{filename}::{function}::{variable_type} {variable_name}:{declared_line}".format(
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
