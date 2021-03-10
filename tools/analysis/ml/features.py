import numpy
from scipy.stats import entropy


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
            input_size_correlation_features['max_value_to_input_size_correlation'] = r[0, 1]


def derive_counter_features(var):

    def smooth(arr):
        smoothed = []
        value_sum = 0
        for value in arr:
            if value != 0 and value_sum != 0 \
                and (value / abs(value)) != (value_sum / abs(value_sum)) \
                    and abs(value) == abs(value_sum):
                value_sum = 0
                continue
            else:
                value_sum += value
                smoothed.append(value)

        return smoothed

    def counter_segments(arr):
        segments = []

        diff_sum = 0
        segment = []
        for i in range(0, len(arr) - 1):
            diff = arr[i + 1] - arr[i]

            if diff != 0 and diff_sum != 0 and (diff / abs(diff)) != (diff_sum / abs(diff_sum)):
                segment.append(arr[i])
                segments.append(segment)

                diff_sum = 0
                segment = []
            else:
                diff_sum += diff
                segment.append(arr[i])

        segment.append(arr[len(arr) - 1])
        segments.append(segment)

        return segments

    def lag_one_autocorrelate(x):
        one_less_at_end = x[:-1]
        one_less_at_beginning = x[1:]

        if numpy.var(one_less_at_end) > 0 and numpy.var(one_less_at_beginning) > 0:
            return numpy.corrcoef(one_less_at_end, one_less_at_beginning)[0, 1]
        elif len(x) > 2 and numpy.var(one_less_at_end) == 0 and numpy.var(one_less_at_beginning) == 0:
            return 1

        return 0

    # TODO: how many false negatives do we have??? need to make a test program with all kinds of counters... see
    # TODO: which ones aren't picked up

    if 'features' not in var or 'general' not in var['features']:
        derive_general_features(var)

    general_features = var['features']['general']

    if 'counter' not in var['features']:
        var['features']['counter'] = {
            'max_values': [],
            'input_sizes': [],
            'max_values_variance': 0,
            'input_sizes_variance': 0,
            'max_value_to_input_size_correlation': 0,
            'average_delta': 0,
            'varying_deltas': False,
            'average_value_set_cardinality_ratio': 0,
            'loop_sequence_proportion': 0,
            'loop_sequence_proportion_filtered': 0,
            'jaggedness_full': None,
            'jaggedness_filtered': None,
            'lag_one_autocorr_full': 0,
            'lag_one_autocorr_filtered': 0,
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
    proportion_sum = 0
    combined_trace = []
    combined_trace_counter_segments = []
    combined_filtered_trace = []
    combined_filtered_trace_counter_segments = []
    traces = []
    for trace in var['info']['traces']:
        trace_values = [int(item['variable_value']) for item in trace['items']]
        proportion_sum += len(set(trace_values)) / general_features['num_unique_values']

        if len(trace_values) < 2:
            continue

        max_values.append(max([int(item['variable_value']) for item in trace['items']]))
        input_sizes.append(trace['input_size'])

        combined_trace += trace_values
        combined_trace_counter_segments += counter_segments(trace_values)

        new_trace = []
        previous_value = None
        for item in trace['items']:
            current_value = int(item['variable_value'])
            if current_value != previous_value:
                new_trace.append(current_value)
                previous_value = current_value

        if len(new_trace) > 1:
            traces.append(new_trace)
            combined_filtered_trace += new_trace
            combined_filtered_trace_counter_segments += counter_segments(new_trace)

    counter_features['average_value_set_cardinality_ratio'] = proportion_sum / general_features['num_traces']

    if len(combined_trace) > 0:
        filtered_segments = [s for s in combined_trace_counter_segments if len(s) > 2]
        if len(filtered_segments) > 0:
            counter_features['lag_one_autocorr_full'] = numpy.mean([
                lag_one_autocorrelate(s) for s in filtered_segments
            ])

    combined_deltas = []
    if len(combined_filtered_trace) > 0:
        filtered_segments = [s for s in combined_filtered_trace_counter_segments if len(s) > 2]
        if len(filtered_segments) > 0:
            counter_features['lag_one_autocorr_filtered'] = numpy.mean([
                lag_one_autocorrelate(s) for s in filtered_segments
            ])
            counter_features['loop_sequence_proportion_filtered'] = sum(
                [len(s) for s in combined_filtered_trace_counter_segments if len(s) > 1]
            ) / len(combined_filtered_trace)

            if len(combined_trace) > 0:
                counter_features['loop_sequence_proportion'] = sum(
                    [len(s) for s in combined_filtered_trace_counter_segments if len(s) > 1]
                ) / len(combined_trace)

        for s in [s for s in combined_filtered_trace_counter_segments if len(s) > 1]:
            combined_deltas += numpy.diff(s).tolist()

    # TODO: it appears that for certain enums d2s ends up being empty. I suspect it's because there are no counter
    # TODO: segments > 1 because stuff jumps around so much. check requiredSize in BnConvert.c end up getting a lot of
    # TODO: deltas in d2s when combined deltas just ends up being 1??

    if len(combined_deltas) > 1:
        counter_features['average_delta'] = numpy.mean(combined_deltas)
        if len(set(combined_deltas)) > 1:
            counter_features['varying_deltas'] = True

    combined_trace_deltas_smoothed = smooth(numpy.diff(combined_trace))
    if len(combined_trace_deltas_smoothed) > 0:
        stddev = numpy.std(combined_trace_deltas_smoothed)
        abs_mean = numpy.abs(numpy.mean(combined_trace_deltas_smoothed))

        if abs_mean > 0:
            counter_features['jaggedness_full'] = stddev / abs_mean

        counter_features['lag_one_autocorr_full'] = lag_one_autocorrelate(combined_trace)

    combined_filtered_trace_deltas_smoothed = smooth(numpy.diff(combined_filtered_trace))
    if len(combined_filtered_trace_deltas_smoothed) > 0:
        stddev = numpy.std(combined_filtered_trace_deltas_smoothed)
        abs_mean = numpy.abs(numpy.mean(combined_filtered_trace_deltas_smoothed))

        if abs_mean > 0:
            counter_features['jaggedness_filtered'] = stddev / abs_mean

    if len(max_values) > 0 and len(input_sizes) > 0:
        counter_features['max_values_variance'] = numpy.var(max_values)
        counter_features['input_sizes_variance'] = numpy.var(input_sizes)
        if counter_features['max_values_variance'] > 0 and counter_features['input_sizes_variance'] > 0:
            r = numpy.corrcoef(max_values, input_sizes)
            counter_features['max_value_to_input_size_correlation'] = r[0, 1]


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
        enum_features['times_modified_to_input_size_correlation'] = r[0, 1]
