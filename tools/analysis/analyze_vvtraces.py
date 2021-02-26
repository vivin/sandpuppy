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

            if len(classified_variables['static_counters']) > 0:
                print("")
                print("    Static Counters:")
                for variable in classified_variables['static_counters']:
                    print("      {fqn}".format(fqn=variable['fqn']))

            if len(classified_variables['dynamic_counters']) > 0:
                print("")
                print("    Dynamic Counters:")
                for variable in classified_variables['dynamic_counters']:
                    print("      {fqn}".format(fqn=variable['fqn']))

            if len(classified_variables['input_size_counters']) > 0:
                print("")
                print("    Counters correlated with input size:")
                for variable in classified_variables['input_size_counters']:
                    print("      {fqn}".format(fqn=variable['fqn']))

            if len(classified_variables['correlated_with_input_size']) > 0:
                print("")
                print("    Variables correlated with input size:")
                for variable in classified_variables['correlated_with_input_size']:
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
    # TODO: other things you can do: compare trace of variable with trace of another variable. see if one is proper
    # TODO: subset maybe? compare timestampts too?


def classify_variables(variables):

    def is_constant(var):
        # Pretty simple. If the variable is only modified at one place and only has one unique value, it is a constant.
        return var['analysis']['num_modified_lines'] == 1 and var['analysis']['num_unique_values'] == 1

    def is_correlated_with_input_size(var):
        # We are looking for variables whose values may reflect some correlation with the input size. Essentially we
        # are looking for "size", "count", or "length" type variables. We only focus on the maximum value (per trace)
        # of these variables and see if they are correlated with input size.
        max_values = []
        for trace in var['info']['traces']:
            if len(trace['items']) > 0:
                max_values.append(max([int(item['variable_value']) for item in trace['items']]))

        input_sizes = var['analysis']['input_sizes']
        if len(input_sizes) == 0 or len(max_values) == 0:
            return False

        input_sizes_variance = var['analysis']['input_sizes_variance']
        max_values_variance = numpy.var(max_values)

        if input_sizes_variance == 0 or max_values_variance == 0:
            return False

        r = numpy.corrcoef(input_sizes, max_values)
        if r[0, 1] >= 0.25 and r[1, 0] >= 0.25:
            return True

        return False

    def is_counter(var):

        counter = True
        total_times_modified = sum(var['analysis']['times_modified'])
        num_values_part_of_loop = 0

        # Keep track of the number of iterations this variable goes through, each time it goes through a loop. Basically
        # this is the number of times a variable is incremented/decremented until it reaches its limit. We do this so
        # that we can exclude those variables that appear to go through only one iteration. This typically happens in
        # the case of boolean-like variables that flip between 0 and 1, or in general, variables that flip between two
        # fixed values.
        combined_iterations = []

        # Keep track of the deltas of the variable values between one iteration and the next, until the limit. Note that
        # if val[t + 1] is the start of a new iteration, we do not store the delta between val[t] and val[t + 1]. The
        # reason we maintain these deltas is to exclude variables that may increase (or decrease) monotonically but
        # at very high rates. Currently we exclude any variable that has a mean delta (across all traces) greater than
        # 255.
        combined_deltas = []
        for trace in var['info']['traces']:

            # Ignore any trace that has less than two items because it is clearly modified only once.
            if len(trace['items']) < 2:
                continue

            # Keep track of the deltas within a "loop"
            deltas = []

            # The direction of the loop. Calculated based on val[t + 1] - val[t], where t is the trace corresponding to
            # the first iteration of the loop. This helps us handle both incrementing and decrementing loops and can
            # also help us detect when a loop might have ended.
            loop_direction = 0

            # Boolean to indicate that we have started a new loop
            new_loop = True

            #if 'digestSize' in var['fqn'] and 'AlgorithmTests.c' in var['fqn']:
            #    print([item['variable_value'] for item in trace['items']])

            index = 0
            while index < len(trace['items']) - 1 and counter:
                current_value = int(trace['items'][index]['variable_value'])
                next_value = int(trace['items'][index + 1]['variable_value'])

                # Calculate the delta between the current value and the next value. If the delta is 0 (i.e. no change
                # between current and next value), we continue the loop. The intent is to ignore "runs" of the same
                # value. This is because we can have situations where a legitimate counter gets set to the starting
                # value multiple times, but doesn't increment/decrement because the starting value is outside the bounds
                # of the loop's limit. However it could be that at some point it does eventually start incrementing or
                # decrementing, so we want to be able to detect that. TODO: this is a bit of a problem because it is now
                # TODO: classifying player_col, delta_row, etc. as counters. which sort of makes sense because they do
                # TODO: monotonically increase etc or decrease. and by ignoring runs of values we end up only focusing
                # TODO: on those parts that increment or decrement. Maybe for related variables we need to ignore
                # TODO: whether they have been classified? I think for counters you should check if within a loop
                # TODO: everything increments by the same amount. because in general even if you have a random string
                # TODO: of numbers, you will find some monotonically increasing/decreasing sequence. and so any variable
                # TODO: can potentially be a counter. so I think the issue here is that if you negatively classify
                # TODO: variables with runs of values, you risk ignoring variables that maybe are counters but start
                # TODO: off never looping, and so just have a run of initial values, but then eventually does start
                # TODO: looping. however doing so causes you to also classify more or less anything with at least one
                # TODO: monotonically increasing sequence as a counter. so i guess maybe you need to compare how many
                # TODO: percentage of traces get classified as counters vs not? ugh. you know what maybe we just
                # TODO: ignore variables that start off with runs of values... or have runs of values... it's worth
                # TODO: negatively classifying those if it makes the other classifications more accurate. yeah...
                # TODO: actually, if you make the assumption that the counter is always going to increment by a fixed
                # TODO: value each time in the loop, i think that is fine. because, of course, you could potentially
                # TODO: have loops where the counter increments by different values each time, but those are kind of
                # TODO: rare. and if they are worth maximizing, that is, if they end up being correlated to input size
                # TODO: somehow, we can detect that. !!! OK so it doesn't classify message_type as a counter but it does
                # TODO: classify player_col and stuff like that as counters... which makes sense. delta_col can also be
                # TODO: a counter as it can go from -1 to 0 to 1 :/. maybe you calculate how many elements are part of
                # TODO: loop sequence as a proportion of the total number of elements in the trace? because an actual
                # TODO: loop variable should show a high proportion of that I think.
                # TODO: maybe you can just leave this the way it is. i guess the question is what do we want to
                # TODO: instrument based on the classification? so what if the player_col etc gets classified as a
                # TODO: counter? it still gets classified as related to player_row and so on. so yes, we could
                # TODO: instrument something useless but since we will be running things in parallel maybe that's not
                # TODO: so bad as we will be running multiple instrumented binaries. maybe one maximizes the player_col
                # TODO: "counter" and another does the hash combination of player_col and player_row. so maybe not a
                # TODO: big deal. but what you can do is exclude constants from related variables. since there is no
                # TODO: need to look at them. also maybe even variables correlated with input size... you could ignore
                # TODO: those too. honestly, try incorporating the number of elements that are part of a monotonically
                # TODO: increasing/decreasing sequence of length > 2 as a proportion of total number of elements of all
                # TODO: traces (or maybe just for a process?? try both and see what happens). So we could either
                # TODO: calculate the percentage of traces with proportion of elements > threshold. or we could
                # TODO: calculate the proportion of elements part of a sequences wrt the total number of sequences from
                # TODO: all traces and see if that is over a threshold? but this is not as bad as I initially thought.
                # TODO: the classification is still pretty accurate.
                delta = next_value - current_value
                #if 'digestSize' in var['fqn'] and 'AlgorithmTests.c' in var['fqn']:
                #    print(next_value, " - ", current_value, " = ", delta)
                if delta == 0:
                    index += 1
                    continue

                # We need to handle the cases where we have 0, 0, 0, 0, 1, 2, 3, 4 or 5, 5, 5, 0, 1, 2, 3, 4. While the
                # direction from 0 to 1 is the same as the rest of the loop, the direction from 5 to 0 isn't. So how can
                # we ignore the transition from 5 to 0? Let's compare it to the transition from 0 to 1. If it is the
                # same direction, we keep going. Otherwise
                # if new_loop and trace['items'][index]['']

                # If this is the start of a new loop establish the loop direction by calculating the sign of
                # val[t + 1] - val[t] and set it to prev_sign.
                if new_loop:
                    loop_direction = delta / abs(delta)
                    new_loop = False

                # Calculate the direction based on the sign of val[t + 1] - val[t]
                direction = delta / abs(delta)

                if direction == loop_direction:
                    # If the direction is the same as the loop direction (i.e, we continue to increment/decrement) add
                    # the delta to our list of deltas for this loop, and to the list of combined deltas as well.
                    deltas.append(abs(delta))
                    combined_deltas.append(abs(delta))

                    if (index + 1) == len(trace['items']) - 1:
                        combined_iterations.append(len(deltas))
                        num_values_part_of_loop += len(deltas) + 1
                        counter = len(set(deltas)) == 1
                elif len(deltas) == 1:
                    #print("looped only once")
                    # If the loop looped only once before the direction changed we will start a new loop and also pop
                    # the last delta out of the combined deltas. This is because we want to ignore situations where
                    # a variable ends up flipping between two values. While it could be considered a one bit counter
                    # it's probably not an actual counter.
                    combined_deltas.pop()
                    deltas = []
                    new_loop = True
                elif len(set(deltas)) == 1:
                    #print("more than one delta, loop dir changed, and deltas are all of one value")
                    # If the direction of the loop has changed and we have more than one delta (meaning the loop looped
                    # more than once) we are at the end of the loop. Let us check the deltas to make sure that they are
                    # all the same values. If not, we will not classify this as a counter.
                    combined_iterations.append(len(deltas))
                    num_values_part_of_loop += len(deltas) + 1
                    deltas = []
                    new_loop = True

                else:
                    #print("not counter because no delta")
                    counter = False

                index += 1

        # TODO: examine digestSize in AlgorithmTests.c why is it a static counter?
        # TODO: maybe if max(combined_iterations) is 1, you can check the proportion value?
        # TODO: look at dType in CommandDispatcher.c in CommandDispatcher log stuff out... but dType in
        # TODO: parseHandleBuffer is recognized as enum. in there check why command.handleNum and type are correlated
        # TODO: with input size. in ExecCommand.c see why command.index and command.parameterSize are correlated
        # TODO: with input size. index shouldn't be i imagine??

        proportion_part_of_loop = (num_values_part_of_loop / total_times_modified)
        #print("      ", "counter =", counter, " len(combined_deltas) =", len(combined_deltas),
        #      " mean combined deltas =", numpy.mean(combined_deltas) if len(combined_deltas) > 0 else 0,
        #      " len(combined_iterations) =", len(combined_iterations),
        #      " max combined iterations =", max(combined_iterations) if len(combined_iterations) > 0 else 0,
        #      " proportion_part of loop =", proportion_part_of_loop, "\n")
        # The check for <= 255 is to ignore things that have huge jumps in value
        return counter and len(combined_deltas) > 0 and numpy.mean(combined_deltas) <= 255 \
            and len(combined_iterations) > 0 \
            and proportion_part_of_loop > 0.5

    def classify_counter(var):
        # We know it is a counter. But is it a static counter or a dynamic one? Meaning, does it always count
        # up to a fixed value, or does it vary? To find out let's look at the maximum values in the traces.
        counter_max_vals = []
        for trace in var['info']['traces']:
            counter_max_vals.append(max([int(item['variable_value']) for item in trace['items']]))

        counter_max_vals_variance = numpy.var(counter_max_vals)

        input_sizes = var['analysis']['input_sizes']
        input_sizes_variance = var['analysis']['input_sizes_variance']

        # If the counter maximum values are all the same this is a static counter. If the counter maximum values are
        # different but the input sizes are the same, it suggests that the counter is not affected by the input size
        # but counts up to different values, which makes it a dynamic counter.
        #
        # TODO: check if it counts up to the same set of values every time. this also makes it static. Maybe call it
        # TODO: multiple_static.
        #
        # If neither of the variances are zero, then we can see if the maximum values of the counter are correlated with
        # input size. If that is the case this makes it an input-size counter. Otherwise it is a dynamic counter.
        if counter_max_vals_variance == 0:
            return "static"
        elif input_sizes_variance == 0:
            return "dynamic"

        r = numpy.corrcoef(input_sizes, counter_max_vals)
        if r[0, 1] < 0.25 or r[1, 0] < 0.25:
            return "dynamic"
        else:
            return "input_size"

    def is_enum(var):
        if 'analysis' not in var:
            analyze_variable(var)

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

        #print("      Number of times {fqn} is modified is correlated with input size "
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
            counter_class = classify_counter(variable)
            variable['class'] = counter_class + "_counter"
            classified_vars[counter_class + "_counters"].append(variable)
        elif is_correlated_with_input_size(variable):
            variable['class'] = "correlated_with_input_size"
            classified_vars['correlated_with_input_size'].append(variable)
        elif is_enum(variable):
            variable['class'] = "enum"
            classified_vars['enums'].append(variable)

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
