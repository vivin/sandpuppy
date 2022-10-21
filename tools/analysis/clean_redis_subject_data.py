import sys
import redis

from db import redis_trace_db


def main(experiment: str, subject: str, binary: str = None, execution: str = None):
    print("Clearing data for:\n")

    print("Experiment: {experiment}".format(experiment=experiment))
    print("Subject:    {subject}".format(subject=subject))

    client = redis.Redis(host='localhost', port=6379, db=0)

    if execution is None:
        print(f"Deleting {experiment}:{subject}:{binary}...")
        redis_trace_db.delete_experiment_subject_binary(client, experiment, subject, binary)
    else:
        print(f"Deleting {experiment}:{subject}:{binary}:{experiment}...")
        redis_trace_db.delete_experiment_subject_binary_execution(client, experiment, subject, binary, execution)


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Syntax: {script} <experiment> <subject> <binary> [<execution>]".format(
            script=sys.argv[0]
        ))
    else:
        _experiment = sys.argv[1]
        _subject = sys.argv[2]
        _binary = sys.argv[3]

        if len(sys.argv) == 5:
            _execution = sys.argv[4]
        else:
            _execution = None

        main(_experiment, _subject, _binary, _execution)
