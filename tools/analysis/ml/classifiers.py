def is_constant(features):
    if features['times_modified_max'] == 0:
        return False

    num_unique_values = features['num_unique_values']
    most_min_value = features['most_min_value']
    variable_values_set = features['values_set']

    # If the variable takes on only one unique value, it is a constant. However a variable could be defined and then
    # set to its value later. So we also check to see if the variable has two unique values, if the minimum value is
    # zero, and that the two unique values aren't 0 and 1 (we want to classify variables that only take on 0 and 1
    # values as booleans).
    return num_unique_values == 1 or (num_unique_values == 2 and most_min_value == 0 and variable_values_set != {0, 1})


def is_boolean(features):
    if features['times_modified_max'] == 0:
        return False

    num_unique_values = features['num_unique_values']
    variable_values_set = features['values_set']
    return num_unique_values == 2 and variable_values_set == {0, 1}


def is_correlated_with_input_size(features):
    max_values_variance = features['max_values_variance']
    input_sizes_variance = features['input_sizes_variance']
    if max_values_variance == 0 or input_sizes_variance == 0:
        return False

    pearson_coefficient = features['max_value_to_input_size_correlation']
    if pearson_coefficient >= 0.6:
        return True

    return False


def is_counter(features):
    # It's hard to classify counters if the traces aren't long enough. We can end up with a lot of false positives. So
    # we will return False for any variable whose maximum trace-length is less than 3.
    if features['times_modified_max'] < 3:
        return False

    average_delta = features['average_delta']
    loop_sequence_proportion = features['loop_sequence_proportion_filtered']

    return abs(average_delta) <= 255 and loop_sequence_proportion > 0.5


def classify_counter(features):
    if not is_counter(features):
        raise Exception("Cannot determine type of counter variable because is_counter returns False.")

    # We know it is a counter. But is it a static counter or a dynamic one? Meaning, does it always count up to a fixed
    # value, or does it vary? If it counts up to a value, is that value correlated with input size?
    max_values_variance = features['max_values_variance']
    average_value_set_cardinality_ratio = features['average_value_set_cardinality_ratio']
    max_value_to_input_size_correlation = features['max_value_to_input_size_correlation']

    # If the counter maximum values are all the same and the average value set cardinality ratio is 1 (meaning that in
    # every trace the variable takes on the full set of values across all traces) this is a static counter. If the
    # correlation between the maximum value per trace and the corresponding input size is lesser than 0.5, this is a
    # dynamic counter. Otherwise this is an input size counter.
    #
    # TODO: check if it counts up to the same set of values every time. this also makes it static. Maybe call it
    # TODO: multiple_static.
    if max_values_variance == 0 and average_value_set_cardinality_ratio == 1:
        return "static"
    elif max_value_to_input_size_correlation < 0.6:
        return "dynamic"
    else:
        return "input_size"


def is_enum(features):
    # We will look for Pearson coefficients greater than 0.5 to see if the number of times a variable is modified
    # is correlated with input size. Note that one issue is that the input size isn't necessarily the same as the
    # size of the input _actually processed_. The input size we end up reporting from AFL is the size of the input
    # sent to the process and it may fail early due to invalid input. Ideally it would be nice if we were able to
    # ascertain the amount of bytes actually read by the process from either stdin or a file. Not sure if that is
    # possible, though.
    if features['times_modified_to_input_size_correlation'] < 0.5:
        return False

    # This is super sketch, and I probably need to mathematically prove it or something. But anyway, the
    # assumption is that these enum values come from a small set of values, and even if sequential,
    # aren't wildly different in their magnitudes. We have a limit of 255 unique values and so we don't
    # expect those to vary wildly in an enum. For example, it's not likely we will have an enum with
    # values like 0, 1, 2, and then 12355914 or something. So what we'll do is calculate the standard
    # deviation of the log10 of the values and ignore the variable if that value is greater than 1.
    if features['order_of_magnitudes_stddev'] > 1:
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
    if features['num_modified_lines'] == 1 and features['num_unique_values'] <= 255:
        # Deal with case 1:
        # For now we will limit ourselves to variables that have up to 255 unique values
        return True
    elif features['num_modified_lines'] == features['num_unique_values']:
        # Deal with case 2. Basically the number of lines it is modified on should equal the number of
        # unique values it holds
        return True

    return False


def is_enum_deriving_values_from_input(features):
    if not is_enum(features):
        raise Exception("Cannot determine type of enum variable {fqn} because is_enum returns False.")

    # We will look for Pearson coefficients greater than 0.5 to see if the number of times a variable is modified
    # is correlated with input size. Note that one issue is that the input size isn't necessarily the same as the
    # size of the input _actually processed_. The input size we end up reporting from AFL is the size of the input
    # sent to the process and it may fail early due to invalid input. Ideally it would be nice if we were able to
    # ascertain the amount of bytes actually read by the process from either stdin or a file. Not sure if that is
    # possible, though.
    times_modified_to_input_size_correlation = features['times_modified_to_input_size_correlation']
    average_value_set_cardinality_ratio = features['average_value_set_cardinality_ratio']
    return times_modified_to_input_size_correlation >= 0.5 and average_value_set_cardinality_ratio < 1
