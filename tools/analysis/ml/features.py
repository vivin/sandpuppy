import numpy


def derive_general_features(variable):
    if 'features' not in variable:
        variable['features'] = dict()

    if 'general' not in variable['features']:
        variable['features']['general'] = dict()

    general_features = variable['features']['general']

    general_features['num_traces'] = len(variable['info']['traces'])
    general_features['num_modified_lines'] = len(variable['info']['modified_lines'])
    general_features['num_unique_values'] = len(set(variable['info']['variable_values']))

    times_modified = []
    input_sizes = []
    for trace in variable['info']['traces']:
        times_modified.append(len(trace['items']))
        input_sizes.append(trace['input_size'])

    general_features['times_modified'] = times_modified
    general_features['times_modified_variance'] = numpy.var(times_modified) if len(times_modified) > 0 else 0

    general_features['times_modified_min'] = numpy.min(times_modified) if len(times_modified) > 0 else 0
    general_features['times_modified_max'] = numpy.max(times_modified) if len(times_modified) > 0 else 0
    general_features['times_modified_mean'] = numpy.mean(times_modified) if len(times_modified) > 0 else 0
    general_features['times_modified_stddev'] = numpy.std(times_modified) if len(times_modified) > 0 else 0

    general_features['input_sizes'] = input_sizes
    general_features['input_sizes_variance'] = numpy.var(input_sizes) if len(input_sizes) > 0 else 0


def derive_input_size_correlation_features(var):
    if 'correlated_with_input_size' not in var['features']:
        var['features']['correlated_with_input_size'] = {
            'max_values': [],
            'input_sizes': [],
            'max_values_variance': 0,
            'input_sizes_variance': 0,
            'max_value_to_input_size_correlation': 0
        }

    input_size_correlation_features = var['features']['correlated_with_input_size']

    # We are looking for variables whose values may reflect some correlation with the input size. Essentially we
    # are looking for "size" or "length" type variables. We only focus on the maximum value (per trace) and only
    # for those traces that contain either 1 or 2 elements. This is because these variables are either initialized
    # to a value and then left unchanged, or are initialized to zero and then set to to a value and left unchanged.
    # Note that "count" type variables that count up to a value correlated with input size are handled separately.
    max_values = input_size_correlation_features['max_values']
    input_sizes = input_size_correlation_features['input_sizes']
    for trace in var['info']['traces']:
        if 0 < len(trace['items']) < 3:
            max_values.append(max([int(item['variable_value']) for item in trace['items']]))
            input_sizes.append(trace['input_size'])

    if len(max_values) > 0 and len(input_sizes) > 0:
        max_values_variance = numpy.var(max_values)
        input_sizes_variance = numpy.var(input_sizes)

        if max_values_variance > 0 and input_sizes_variance > 0:
            input_size_correlation_features['max_values_variance'] = max_values_variance
            input_size_correlation_features['input_sizes_variance'] = input_sizes_variance

            r = numpy.corrcoef(max_values, input_sizes)
            input_size_correlation_features['max_value_to_input_size_correlation'] = numpy.round(r[0, 1], 2)


def derive_counter_features(var):
    # TODO: how many false negatives do we have??? need to make a test program with all kinds of counters... see
    # TODO: which ones aren't picked up

    if 'features' not in var or 'general' not in var['features']:
        derive_general_features(var)

    general_features = var['features']['general']

    if 'counter' not in var['features']:
        var['features']['counter'] = {
            'combined_deltas': [],
            'max_values': [],
            'input_sizes': [],
            'max_values_variance': 0,
            'input_sizes_variance': 0,
            'max_value_to_input_size_correlation': 0,
            'varying_deltas': False,
            'loop_sequence_proportion': 0
        }

    counter_features = var['features']['counter']

    # If there are no traces, return
    if general_features['num_traces'] < 1:
        return

    max_values = counter_features['max_values']
    input_sizes = counter_features['input_sizes']

    # First we are going to filter out and clean up traces. We ignore any trace with less than two items. Then we
    # will clean up "runs" of values in a trace. Runs of values can happen normally for non-counter variables. But
    # it is possible with counters well if the loop never gets started because the counter variable is initialized
    # to a value that already satisfies the end condition of the loop. By replacing these runs with just a single
    # instance of the repeated value, it is much easier to identify potential loop sequences. We do not have to
    # worry about mis-classifying non-counter variables as counters if they happen have series of values that
    # translate to a valid loop sequence, because we will also calculate the proportion of such values with respect
    # to the total number of values. If this proportion is less than 0.5, we will not consider the variable as a
    # counter. Since in general, counter variables will have a higher proportion of values (if not all) that are
    # part of a loop sequence, this can help us weed out false positives. We will also keep track of the maximum
    # values the counter takes in each trace of length greater than 1 and the corresponding input size. We use
    # these later to calculate the pearson coefficient to see if the counter counts up to a value correlated with
    # input size. It helps us classify the type of counter a variable is if it does indeed end up being a counter.
    traces = []
    for trace in var['info']['traces']:
        if len(trace['items']) < 2:
            continue

        max_values.append(max([int(item['variable_value']) for item in trace['items']]))
        input_sizes.append(trace['input_size'])

        new_trace = []
        previous_value = None
        for item in trace['items']:
            current_value = int(item['variable_value'])
            if current_value != previous_value:
                new_trace.append(current_value)
                previous_value = current_value

        if len(new_trace) > 1:
            traces.append(new_trace)

    if len(max_values) > 0 and len(input_sizes) > 0:
        counter_features['max_values_variance'] = numpy.var(max_values)
        counter_features['input_sizes_variance'] = numpy.var(input_sizes)
        if counter_features['max_values_variance'] > 0 and counter_features['input_sizes_variance'] > 0:
            r = numpy.corrcoef(max_values, input_sizes)
            counter_features['max_value_to_input_size_correlation'] = numpy.round(r[0, 1], 2)
            #print ("correl is ", numpy.round(r[0, 1], 2), counter_features['max_value_to_input_size_correlation'])

    # The total length of all traces
    trace_lengths_sum = sum(general_features['times_modified'])

    # The sum of the lengths of all identified loop sequences across all traces. This is the same as the number of
    # trace elements (basically variable values) across all traces that are part of a loop sequence.
    loop_sequence_lengths_sum = 0

    # Keep track of the deltas between successive values within a single loop sequence.
    deltas = []

    # Keep track of the deltas between successive values from all identified loop sequences. The reason we maintain
    # these deltas is to exclude variables that may increase (or decrease) but at very high rates. Currently we
    # exclude any variable that has a mean delta (across all traces) greater than 255.
    combined_deltas = counter_features['combined_deltas']

    # Now we process our subset of cleaned up traces. The intent is to identify sequences of increasing and
    # decreasing values. There may be multiple such sequences per trace. Based on certain aggregate features of
    # these sequences, we can determine whether the variable might be a counter.
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
        while index < len(trace) - 1:
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
                    counter_features['varying_deltas'] = True

                loop_sequence_lengths_sum += len(deltas) + 1
                deltas = []
                loop_direction = None

            index += 1

    # If the entire trace is a loop sequence, or there is a loop sequence that starts somewhere in the middle of
    # the trace and runs till the end, we will have exited the loop without saving the deltas. If this happens
    # the deltas list will contain elements, so we can handle that case here.
    if len(deltas) > 0:
        if len(set(deltas)) > 1:
            counter_features['varying_deltas'] = True
        loop_sequence_lengths_sum += len(deltas) + 1

    if trace_lengths_sum > 0:
        counter_features['loop_sequence_proportion'] = numpy.round(loop_sequence_lengths_sum / trace_lengths_sum, 2)


def derive_enum_features(var):
    if 'features' not in var or 'general' not in var['features']:
        derive_general_features(var)

    general_features = var['features']['general']

    if 'enum' not in var['features']:
        var['features']['enum'] = {
            'order_of_magnitudes_stddev': 0,
            'times_modified_to_input_size_correlation': 0
        }

    enum_features = var['features']['enum']

    # If there are no traces, return
    if general_features['num_traces'] < 1:
        return

    # We will use the standard deviation of the order of magnitudes to make sure that the distribution of enum
    # values do not vary too wildly. For example, something that takes on values like 1, 2, 4, and then 500000
    # is probably not an enum.
    variable_values = numpy.array(var['info']['variable_values']).astype(numpy.float)
    order_of_magnitudes = [numpy.log10(v) if v > 0 else 0 for v in variable_values]
    enum_features['order_of_magnitudes_stddev'] = numpy.std(order_of_magnitudes)

    # For enum-like variables, we are looking to maximize the combinations in the input. The assumption is that
    # the enum value is derived from some input element, and that there can be multiple such elements. So one way
    # to see if we are dealing with an enum variable is to check if there is a correlation between the number of
    # times the variable is modified invoked and the input size. So our data set we will collect will be two arrays.
    # Each array has an entry per process trace. The first array will holds the number of times a variable was
    # modified, and the second holds corresponding input sizes.
    times_modified = general_features['times_modified']
    times_modified_variance = general_features['times_modified_variance']

    input_sizes = general_features['input_sizes']
    input_sizes_variance = general_features['input_sizes_variance']

    # TODO: counters that flip between just two values end up being misclassified as enums. Need to handle that.
    # TODO: also need to add a test that checks to see if the variable goes through the exact same set of values
    # TODO: in every trace. if that is the case it might not be an enum variable.

    if times_modified_variance > 0 and input_sizes_variance > 0:
        r = numpy.corrcoef(times_modified, input_sizes)
        enum_features['times_modified_to_input_size_correlation'] = numpy.round(r[0, 1], 2)
