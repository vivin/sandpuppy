import numpy


def extract_features(variable):
    features = {
        'num_traces': len(variable['traces_info']['traces']),
        'num_modified_lines': len(variable['traces_info']['modified_lines']),
        'num_unique_values': len(set(variable['traces_info']['variable_values'])),
        'values_set': set(variable['traces_info']['variable_values']),
        'times_modified_variance': 0,
        'times_modified_min': 0,
        'times_modified_max': 0,
        'times_modified_mean': 0,
        'times_modified_stddev': 0,
        'input_sizes_variance': 0,
        'most_min_value': 0,
        'min_values_variance': 0,
        'most_max_value': 0,
        'max_values_variance': 0,
        'max_value_to_input_size_correlation': 0,
        'varying_deltas': False,
        'average_value_set_cardinality_ratio': 0,
        'loop_sequence_proportion': 0,
        'directional_consistency': 0,
        'average_counter_segment_length': 0,
        'average_counter_segment_length_filtered': 0,
        'times_modified_to_input_size_correlation': 0
    }

    # If there are no traces for this variable, return
    if features['num_traces'] < 1:
        return features

    # First we derive some basic features that are useful when deriving additional features. Among these we have
    # max_values, max_values_variance, input_sizes, input_sizes_variance, and max_value_to_input_size_correlation, which
    # can help us identify "size" or "length" type variables, including counters that count up to some value that is
    # correlated with input size.
    times_modified = []
    input_sizes = []
    min_values = []
    max_values = []
    for trace in variable['traces_info']['traces']:
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
        features['most_min_value'] = min(min_values)
        features['min_values_variance'] = numpy.var(min_values)

    if len(max_values) > 0:
        features['most_max_value'] = max(max_values)
        features['max_values_variance'] = numpy.var(max_values)

    features['range'] = (features['most_max_value'] - features['most_min_value'])

    input_sizes_variance = features['input_sizes_variance']
    max_values_variance = features['max_values_variance']

    if max_values_variance > 0 and input_sizes_variance > 0:
        r = numpy.corrcoef(max_values, input_sizes)
        features['max_value_to_input_size_correlation'] = r[0, 1]

    # Now we derive features that can help us identify counters

    # Note that this function will also return segments containing a run of same values if they are present in the
    # array. These are technically not counter segments since the values don't change. However it shouldn't really
    # affect "true" counters as far as roughness measures are concerned, because these segments are still smooth.
    # We do ignore such segments however, when we calculate the loop-sequence proportion since these segments are not
    # part of a loop.
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
    for trace in variable['traces_info']['traces']:
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
        # features['total_counter_segments'] = len(combined_trace_counter_segments)
        # features['total_counter_segments_to_num_traces_ratio'] = \
        #     features['total_counter_segments'] / features['num_traces']

        segments_gt1 = [s for s in combined_trace_counter_segments if len(s) > 1]
        features['average_counter_segment_length'] = numpy.mean([len(s) for s in segments_gt1])

    combined_deltas = []
    if len(combined_filtered_trace) > 0:
        filtered_segments_gt1 = [s for s in combined_filtered_trace_counter_segments if len(s) > 1]
        features['average_counter_segment_length_filtered'] = numpy.mean([len(s) for s in filtered_segments_gt1])

        # This is perhaps analogous to jaggedness metrics in a way. Out of all filtered counter segments of length
        # greater than one, we count the number of segments that progress upward or downward. We then calculate
        # abs(up - down)/(up + down). For counters, this value should generally be close to 1, whereas for enums, which
        # jump around all over the place, the value should be much lower.
        #
        # It's valid to ask why we use the filtered traces here that do not contain runs, instead of unfiltered traces.
        # We could do the same thing we are doing now, with the exception that we would have to examine the entire
        # segment to see if it contains a run (but we could bail out early). So why don't we do that? The problem is
        # that this may end up actually counting negatively against certain valid counters. For example, a loop could
        # have the start and end values set dynamically, and so it is possible to see runs of values when start and
        # end are set such that the loop never executes. If these same values are set repeatedly, we would see a run
        # of "start" values for the counter in the trace. By filtering these out, we lessen the impact. But how does
        # this impact enums? Enums are likely to have runs, so would this affect the quality of this feature when it
        # comes to enums? Not necessarily. Enums are likely to contain segments that move up and down in far more equal
        # proportions than a counter, where one or the other dominates.
        direction_counts = {
            'up': 0,
            'down': 0
        }
        for segment in filtered_segments_gt1:
            diff = segment[1] - segment[0]

            if diff > 0:
                direction_counts['up'] += 1
            else:
                direction_counts['down'] += 1

        features['directional_consistency'] = \
            abs(direction_counts['up'] - direction_counts['down']) / len(filtered_segments_gt1)

        filtered_segments_gt2 = [s for s in combined_filtered_trace_counter_segments if len(s) > 2]
        if len(filtered_segments_gt2) > 0:
            features['loop_sequence_proportion_filtered'] = sum([
                len(s) for s in filtered_segments_gt2
            ]) / len(combined_filtered_trace)

            # Here we don't use counter segments identified in the combined trace because those can include runs of
            # similar values, and so aren't part of a loop.
            if len(combined_trace) > 0:
                features['loop_sequence_proportion'] = sum(
                    [len(s) for s in filtered_segments_gt2]
                ) / len(combined_trace)

        for s in filtered_segments_gt1:
            combined_deltas += numpy.diff(s).tolist()

    if len(combined_deltas) > 1:
        if len(set(combined_deltas)) > 1:
            features['varying_deltas'] = True

    if len(max_values) > 0 and len(input_sizes) > 0:
        features['max_values_variance'] = numpy.var(max_values)
        features['input_sizes_variance'] = numpy.var(input_sizes)
        if features['max_values_variance'] > 0 and features['input_sizes_variance'] > 0:
            r = numpy.corrcoef(max_values, input_sizes)
            features['max_value_to_input_size_correlation'] = r[0, 1]

    # For enum-like variables, we are looking to maximize the combinations in the input. The assumption is that
    # the enum value is derived from some input element, and that there can be multiple such elements. So one way
    # to see if we are dealing with an enum variable is to check if there is a correlation between the number of
    # times the variable is modified invoked and the input size. So our data set we will collect will be two arrays.
    # Each array has an entry per process trace. The first array will holds the number of times a variable was
    # modified, and the second holds corresponding input sizes.
    times_modified_variance = features['times_modified_variance']

    if times_modified_variance > 0 and input_sizes_variance > 0:
        r = numpy.corrcoef(times_modified, input_sizes)
        features['times_modified_to_input_size_correlation'] = r[0, 1]

    return features
