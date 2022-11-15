import sys
import redis
import math


def main(experiment, subject, version, full_subject, run_name):
    print(f"Experiment: {experiment}")
    print(f"Subject: {full_subject}")
    print(f"Run Name: {run_name}\n")

    basic_blocks = set()
    print(f"Loading basic blocks from resources/{subject}-basic-blocks.txt...", end="")
    for line in open(f"resources/{subject}-basic-blocks.txt"):
        basic_blocks.add(line.strip())

    print(f"{len(basic_blocks)} blocks")

    baseline_coverage = set()
    print(f"Loading baseline coverage resources/{subject}-baseline-coverage.txt...", end="")
    for line in open(f"resources/{subject}-baseline-coverage.txt"):
        baseline_coverage.add(line.strip())

    print(f"{len(baseline_coverage)} blocks")

    client = redis.Redis(host='localhost', port=6379, db=0)

    coverage_data = dict()
    coverage_data_over_time = dict()
    print(f"Loading coverage data from each iteration...")

    overall_coverage = set()
    for iteration in range(1, 7):
        print(f"  Loading coverage for iteration {iteration}")

        run_iteration = f"{run_name}-{iteration}"
        key_prefix = f"{experiment}:{full_subject}:{run_iteration}"

        iteration_coverage = [member.decode("utf-8") for member in client.smembers(f"{key_prefix}.coverage")]
        overall_coverage = overall_coverage.union(iteration_coverage)
        coverage_data[f"{run_iteration}"] = overall_coverage

        percentage_improvement = "{:.2f}".format(calculate_improvement(baseline_coverage, overall_coverage) * 100)
        print(f"  Overall coverage: {len(overall_coverage)} ({percentage_improvement}% improvement)")

        # If this is the first iteration, initialize the coverage data for each hour to empty sets. Otherwise set it to
        # the cumulative end coverage of the last iteration
        if iteration == 1:
            coverage_data_over_time[f"{run_iteration}"] = {
                1: set(),
                2: set(),
                3: set(),
                4: set()
            }
        else:
            coverage_data_over_time[f"{run_iteration}"] = {
                1: coverage_data[f"{run_name}-{iteration - 1}"],
                2: coverage_data[f"{run_name}-{iteration - 1}"],
                3: coverage_data[f"{run_name}-{iteration - 1}"],
                4: coverage_data[f"{run_name}-{iteration - 1}"]
            }

        min_timestamp = 0
        iteration_coverage_over_time = client.smembers(f"{key_prefix}.coverage_over_time")
        for timestamp_and_coverage in sorted(iteration_coverage_over_time):
            timestamp, coverage_blocks = timestamp_and_coverage.decode("utf-8").split(",")
            coverage = set(coverage_blocks.split(";"))

            if min_timestamp == 0:
                min_timestamp = timestamp

            hour = 1 + math.floor((int(timestamp) - int(min_timestamp)) / 3600)

            # Because all the pods don't all start at the same time we have situations where we have data for hour 5. So
            # we just combine anything later than hour 4 into hour 4.
            if hour > 4:
                hour = 4

            hour_coverage = coverage_data_over_time[f"{run_iteration}"][hour]
            coverage_data_over_time[f"{run_iteration}"][hour] = hour_coverage.union(coverage)

        # Fill up holes in coverage data at the beginning
        if len(coverage_data_over_time[f"{run_iteration}"][1]) == 0:
            first_hour_with_data = 0
            for hour in range(2, 5):
                if len(coverage_data_over_time[f"{run_iteration}"][hour]) > 0:
                    first_hour_with_data = hour
                    break

            for hour in range(1, first_hour_with_data):
                coverage_data_over_time[f"{run_iteration}"][hour] = \
                    coverage_data_over_time[f"{run_iteration}"][first_hour_with_data]

        # Merge the coverage from hour 1 to hour 4 so as to get cumulative coverage for each hour
        for hour in range(2, 5):
            hour_coverage = coverage_data_over_time[f"{run_iteration}"][hour]
            coverage_data_over_time[f"{run_iteration}"][hour] = \
                hour_coverage.union(coverage_data_over_time[f"{run_iteration}"][hour - 1])

        for hour in range(1, 5):
            hour_coverage = coverage_data_over_time[f"{run_iteration}"][hour]
            print(f"    Hour {hour}: {len(hour_coverage)}")

        print("")


def calculate_improvement(baseline_coverage, coverage):
    return (len(coverage) - len(baseline_coverage)) / len(baseline_coverage)


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Syntax: {script} <experiment> <subject>[:<version>] <run-name> ".format(script=sys.argv[0]))
    else:
        subject_version = sys.argv[2].split(":")

        _subject = subject_version[0]
        _version = None
        _full_subject = _subject
        if len(subject_version) > 1:
            _version = subject_version[1]
            _full_subject = f"{_subject}-{_version}"

        main(sys.argv[1], _subject, _version, _full_subject, sys.argv[3])
