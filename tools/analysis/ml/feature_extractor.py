import numpy


def extract_features(variable):
    features = {
        'num_traces': len(variable['info']['traces']),
        'num_modified_lines': len(variable['info']['modified_lines']),
        'num_unique_values': len(set(variable['info']['variable_values'])),
        'values_set': set(variable['info']['variable_values']),
        'times_modified': [],
        'times_modified_variance': 0,
        'times_modified_min': 0,
        'times_modified_max': 0,
        'times_modified_mean': 0,
        'times_modified_stddev': 0,
        'input_sizes': [],
        'input_sizes_variance': 0,
        'min_values': [],
        'min_values_variance': 0,
        'max_values': [],
        'max_values_variance': 0,
        'max_value_to_input_size_correlation': 0,
        'average_delta': 0,
        'varying_deltas': False,
        'average_value_set_cardinality_ratio': 0,
        'loop_sequence_proportion': 0,
        'loop_sequence_proportion_filtered': 0,
        'average_counter_segment_length': 0,
        'average_counter_segment_length_filtered': 0,
        'jaggedness_full': None,
        'jaggedness_filtered': None,
        'lag_one_autocorr_full': 0,
        'lag_one_autocorr_filtered': 0,
        'order_of_magnitudes_stddev': 0,
        'times_modified_to_input_size_correlation': 0
    }

    # If there are no traces for this variable, return
    if features['num_traces'] < 1:
        return features

    # First we derive some basic features that are useful when deriving additional features. Among these we have
    # max_values, max_values_variance, input_sizes, input_sizes_variance, and max_value_to_input_size_correlation, which
    # can help us identify "size" or "length" type variables, including counters that count up to some value that is
    # correlated with input size.
    times_modified = features['times_modified']
    input_sizes = features['input_sizes']
    min_values = features['min_values']
    max_values = features['max_values']
    for trace in variable['info']['traces']:
        trace_values = trace['values']
        times_modified.append(len(trace_values))
        if len(trace_values) > 0:
            input_sizes.append(trace['input_size'])
            min_values.append(min(trace_values))
            max_values.append(max(trace_values))

    if len(times_modified) > 0:
        features['times_modified_variance'] = numpy.var(times_modified)
        features['times_modified_min'] = numpy.min(times_modified)
        features['times_modified_max'] = numpy.max(times_modified)
        features['times_modified_mean'] = numpy.mean(times_modified)
        features['times_modified_stddev'] = numpy.std(times_modified)

    if len(input_sizes) > 0:
        features['input_sizes_variance'] = numpy.var(input_sizes)

    if len(min_values) > 0:
        features['min_values_variance'] = numpy.var(min_values)

    if len(max_values) > 0:
        features['max_values_variance'] = numpy.var(max_values)

    input_sizes_variance = features['input_sizes_variance']
    max_values_variance = features['max_values_variance']

    if max_values_variance > 0 and input_sizes_variance > 0:
        r = numpy.corrcoef(max_values, input_sizes)
        features['max_value_to_input_size_correlation'] = r[0, 1]

    # Now we derive features that can help us identify counters

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
    proportion_sum = 0
    combined_trace = []
    combined_trace_counter_segments = []
    combined_filtered_trace = []
    combined_filtered_trace_counter_segments = []
    traces = []
    for trace in variable['info']['traces']:
        trace_values = trace['values']
        proportion_sum += len(set(trace_values)) / features['num_unique_values']

        if len(trace_values) < 2:
            continue

        combined_trace += trace_values
        combined_trace_counter_segments += counter_segments(trace_values)

        new_trace = []
        previous_value = None
        for current_value in trace_values:
            if current_value != previous_value:
                new_trace.append(current_value)
                previous_value = current_value

        if len(new_trace) > 1:
            traces.append(new_trace)
            combined_filtered_trace += new_trace
            combined_filtered_trace_counter_segments += counter_segments(new_trace)

    features['average_value_set_cardinality_ratio'] = proportion_sum / features['num_traces']

    if len(combined_trace) > 0:
        features['average_counter_segment_length'] = numpy.mean(
            [len(s) for s in combined_trace_counter_segments if len(s) > 1]
        )
        filtered_segments_gt2 = [s for s in combined_trace_counter_segments if len(s) > 2]
        if len(filtered_segments_gt2) > 0:
            features['lag_one_autocorr_full'] = numpy.mean([
                lag_one_autocorrelate(s) for s in filtered_segments_gt2
            ])

    combined_deltas = []
    if len(combined_filtered_trace) > 0:
        filtered_segments_gt1 = [s for s in combined_filtered_trace_counter_segments if len(s) > 1]
        features['average_counter_segment_length_filtered'] = numpy.mean([len(s) for s in filtered_segments_gt1])

        filtered_segments_gt2 = [s for s in combined_filtered_trace_counter_segments if len(s) > 2]
        if len(filtered_segments_gt2) > 0:
            features['lag_one_autocorr_filtered'] = numpy.mean([
                lag_one_autocorrelate(s) for s in filtered_segments_gt2
            ])
            features['loop_sequence_proportion_filtered'] = sum(
                [len(s) for s in filtered_segments_gt1]
            ) / len(combined_filtered_trace)

            if len(combined_trace) > 0:
                features['loop_sequence_proportion'] = sum(
                    [len(s) for s in filtered_segments_gt1]
                ) / len(combined_trace)

        for s in filtered_segments_gt1:
            combined_deltas += numpy.diff(s).tolist()

    if len(combined_deltas) > 1:
        features['average_delta'] = numpy.mean(combined_deltas)
        if len(set(combined_deltas)) > 1:
            features['varying_deltas'] = True

    combined_trace_deltas_smoothed = smooth(numpy.diff(combined_trace))
    if len(combined_trace_deltas_smoothed) > 0:
        stddev = numpy.std(combined_trace_deltas_smoothed)
        abs_mean = numpy.abs(numpy.mean(combined_trace_deltas_smoothed))

        if abs_mean > 0:
            features['jaggedness_full'] = stddev / abs_mean

        features['lag_one_autocorr_full'] = lag_one_autocorrelate(combined_trace)

    combined_filtered_trace_deltas_smoothed = smooth(numpy.diff(combined_filtered_trace))
    if len(combined_filtered_trace_deltas_smoothed) > 0:
        stddev = numpy.std(combined_filtered_trace_deltas_smoothed)
        abs_mean = numpy.abs(numpy.mean(combined_filtered_trace_deltas_smoothed))

        if abs_mean > 0:
            features['jaggedness_filtered'] = stddev / abs_mean

    if len(max_values) > 0 and len(input_sizes) > 0:
        features['max_values_variance'] = numpy.var(max_values)
        features['input_sizes_variance'] = numpy.var(input_sizes)
        if features['max_values_variance'] > 0 and features['input_sizes_variance'] > 0:
            r = numpy.corrcoef(max_values, input_sizes)
            features['max_value_to_input_size_correlation'] = r[0, 1]

    # We derive some additional features that can help us identify enums

    # We will use the standard deviation of the order of magnitudes to make sure that the distribution of enum
    # values do not vary too wildly. For example, something that takes on values like 1, 2, 4, and then 500000
    # is probably not an enum.
    variable_values = variable['info']['variable_values']
    order_of_magnitudes = [numpy.log10(v) if v > 0 else 0 for v in variable_values]
    features['order_of_magnitudes_stddev'] = numpy.std(order_of_magnitudes)

    # For enum-like variables, we are looking to maximize the combinations in the input. The assumption is that
    # the enum value is derived from some input element, and that there can be multiple such elements. So one way
    # to see if we are dealing with an enum variable is to check if there is a correlation between the number of
    # times the variable is modified invoked and the input size. So our data set we will collect will be two arrays.
    # Each array has an entry per process trace. The first array will holds the number of times a variable was
    # modified, and the second holds corresponding input sizes.
    times_modified_variance = features['times_modified_variance']

    # TODO: add second roughness/jaggedness measure.

    if times_modified_variance > 0 and input_sizes_variance > 0:
        r = numpy.corrcoef(times_modified, input_sizes)
        features['times_modified_to_input_size_correlation'] = r[0, 1]

    return features
