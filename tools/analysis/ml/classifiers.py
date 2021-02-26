import numpy
from ml import features


def is_constant(var):
    if 'features' not in var or 'general' not in var['features']:
        raise Exception(
            "No general features found for variable {fqn}. Please call derive_general_features first.".format(
                fqn=var['fqn']
            )
        )

    general_features = var['features']['general']

    # Pretty simple. If the variable is only modified at one place and only has one unique value, it is a constant.
    return general_features['num_modified_lines'] == 1 and general_features['num_unique_values'] == 1


def is_correlated_with_input_size(var):
    if 'features' not in var or 'correlated_with_input_size' not in var['features']:
        raise Exception(
            "No input-size correlation features found for variable {fqn}. Please call "
            "derive_input_size_correlation_features first.".format(
                fqn=var['fqn']
            )
        )

    input_size_correlation_features = var['features']['correlated_with_input_size']

    max_values = input_size_correlation_features['max_values']
    input_sizes = input_size_correlation_features['input_sizes']
    if len(max_values) == 0 or len(input_sizes) == 0:
        return False

    max_values_variance = input_size_correlation_features['max_values_variance']
    input_sizes_variance = input_size_correlation_features['input_sizes_variance']
    if max_values_variance == 0 or input_sizes_variance == 0:
        return False

    pearson_coefficient = input_size_correlation_features['max_value_to_input_size_correlation']
    if pearson_coefficient >= 0.5:
        return True

    return False


def is_counter(var):
    if 'features' not in var or 'counter' not in var['features']:
        raise Exception(
            "No counter features found for variable {fqn}. Please call derive_counter_features first.".format(
                fqn=var['fqn']
            )
        )

    counter_features = var['features']['counter']
    combined_deltas = counter_features['combined_deltas']
    loop_sequence_proportion = counter_features['loop_sequence_proportion']

    # print("      ", "counter =", counter, " len(combined_deltas) =", len(combined_deltas),
    #      " mean combined deltas =", numpy.mean(combined_deltas) if len(combined_deltas) > 0 else 0,
    #      " proportion_part of loop =", loop_sequence_proportion, "\n")
    # The check for <= 255 is to ignore things that have huge jumps in value
    return len(combined_deltas) > 0 and numpy.mean(combined_deltas) <= 255 and loop_sequence_proportion > 0.5


def classify_counter(var):
    if 'features' not in var or 'counter' not in var['features']:
        raise Exception(
            "No counter features found for variable {fqn}. Please call derive_counter_features first.".format(
                fqn=var['fqn']
            )
        )

    if not is_counter(var):
        raise Exception(
            "Cannot determine what type of counter variable {fqn} is because it is_counter returns False.".format(
                fqn=var['fqn']
            )
        )

    # We know it is a counter. But is it a static counter or a dynamic one? Meaning, does it always count
    # up to a fixed value, or does it vary? If it counts up to a value, is that value correlated with input size?
    counter_features = var['features']['counter']

    max_values_variance = counter_features['max_values_variance']
    input_sizes_variance = counter_features['input_sizes_variance']

    # If the counter maximum values are all the same this is a static counter. If the counter maximum values are
    # different but the input sizes are the same, it suggests that the counter is not affected by the input size
    # but counts up to different values, which makes it a dynamic counter.
    #
    # TODO: check if it counts up to the same set of values every time. this also makes it static. Maybe call it
    # TODO: multiple_static.
    #
    # If neither of the variances are zero, then we can see if the maximum values of the counter are correlated with
    # input size. If that is the case this makes it an input-size counter. Otherwise it is a dynamic counter.
    if max_values_variance == 0:
        return "static"
    elif input_sizes_variance == 0:
        return "dynamic"

    if counter_features['max_value_to_input_size_correlation'] < 0.5:
        return "dynamic"
    else:
        return "input_size"


def is_enum(var):
    if 'features' not in var or 'enum' not in var['features']:
        features.derive_enum_features(var)

    enum_features = var['features']['enum']
    general_features = var['features']['general']

    # We will look for Pearson coefficients greater than 0.25 to see if the number of times a variable is modified
    # is correlated with input size. Note that one issue is that the input size isn't necessarily the same as the
    # size of the input _actually processed_. The input size we end up reporting from AFL is the size of the input
    # sent to the process and it may fail early due to invalid input. Ideally it would be nice if we were able to
    # ascertain the amount of bytes actually read by the process from either stdin or a file. Not sure if that is
    # possible, though.
    if enum_features['times_modified_to_input_size_correlation'] < 0.25:
        return False

    # This is super sketch, and I probably need to mathematically prove it or something. But anyway, the
    # assumption is that these enum values come from a small set of values, and even if sequential,
    # aren't wildly different in their magnitudes. We have a limit of 255 unique values and so we don't
    # expect those to vary wildly in an enum. For example, it's not likely we will have an enum with
    # values like 0, 1, 2, and then 12355914 or something. So what we'll do is calculate the standard
    # deviation of the log10 of the values and ignore the variable if that value is greater than 1.
    # TODO: move this before previous check and see if anything changes
    if enum_features['order_of_magnitudes_stddev'] > 1:
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
    if general_features['num_modified_lines'] == 1 and general_features['num_unique_values'] <= 255:
        # Deal with case 1:
        # For now we will limit ourselves to variables that have up to 255 unique values
        return True
    elif general_features['num_modified_lines'] == general_features['num_unique_values']:
        # Deal with case 2. Basically the number of lines it is modified on should equal the number of
        # unique values it holds
        return True

    return False
