package vvdump;

use strict;
use warnings;
use POSIX qw(mkfifo);

use Log::Simple::Color;
use DBI;

my $log = Log::Simple::Color->new;

my $NAMED_PIPE_PATH = "/tmp/vvdump";

my $db = "phd";
my $host = "127.0.0.1";
my $port = 5432;
my $username = "phd";
my $password = "phd";

my $EXPERIMENT_NAME = 0;
my $SUBJECT = 1;
my $BINARY_CONTEXT = 2;
my $EXEC_CONTEXT = 3;
my $PID_IDX = 4;
my $FILENAME = 5;
my $EXIT_STATUS = 5;
my $FUNCTION_NAME = 6;
my $INPUT_SIZE = 6;
my $VARIABLE_NAME = 7;
my $DECLARED_LINE = 8;
my $MODIFIED_LINE = 9;
my $TIMESTAMP = 10;
my $VARIABLE_TYPE = 11;
my $VARIABLE_VALUE = 12;

my $DB_EXPERIMENT_NAME = 0;
my $DB_SUBJECT = 1;
my $DB_BINARY_CONTEXT = 2;
my $DB_EXEC_CONTEXT = 3;
my $DB_PID_IDX = 4;
my $DB_EXIT_STATUS = 5;
my $DB_INPUT_SIZE = 6;
my $DB_FILENAME = 7;
my $DB_FUNCTION_NAME = 8;
my $DB_VARIABLE_NAME = 9;
my $DB_DECLARED_LINE = 10;
my $DB_MODIFIED_LINE = 11;
my $DB_TIMESTAMP = 12;
my $DB_VARIABLE_TYPE = 13;
my $DB_VARIABLE_VALUE = 14;

my $NUM_TRACE_COMPONENTS = 15;
my $NUM_END_TRACE_COMPONENTS = 8;

#
# TODO: all the logs aren't making it through. for example, trim_case end logs aren't coming through... although at least
# TODO: one log does show up meaning that it does get executed. afl-fuzz writes it to the pipe but it doesn't show up. why??
# TODO: so I did fix the loop issue in time_case. run_target was being called in a loop there and I didn't account for it.
# TODO: however there are still traces that aren't ending. need to figure out why. happens in calibrate_case maybe and some
# TODO: other function. note that it is possible that we're just losing data too :/ maybe perl script can't keep up?!

my $TRACE_INSERT_STATEMENT = "INSERT INTO vvdump VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
my $END_TRACE_UPDATE_STATEMENT = "UPDATE vvdump SET exit_status = ?, input_size = ? WHERE pid = ?";
my $DELETE_TRACE_STATEMENT = "DELETE FROM vvdump WHERE exit_status = 'unknown' AND pid = ?";

open my $l, ">", "/tmp/vvdlog";

my $pids = {};

sub process {
    if (! -e $NAMED_PIPE_PATH) {
        mkfifo($NAMED_PIPE_PATH, 0700) or die "Could not create named pipe at $NAMED_PIPE_PATH: $!";
    }

    # pipe opened in rw mode so that it remains open even after we have read stuff
    open my $named_pipe_fh, "+<", $NAMED_PIPE_PATH or die "Could not open named pipe at $NAMED_PIPE_PATH: $!";

    $log->info("Opened named pipe at $NAMED_PIPE_PATH.");

    my $pid = fork;
    return $pid if $pid;

    $log->info("Started child process to read and process data from named pipe at $NAMED_PIPE_PATH");

    my $dbh = DBI->connect(
        "dbi:Pg:dbname=$db;host=$host;port=$port",
        $username,
        $password,
        { AutoCommit => 1, RaiseError => -1 }
    ) or die $DBI::errstr;

    my $trace_insert = $dbh->prepare($TRACE_INSERT_STATEMENT);
    my $end_trace_update = $dbh->prepare($END_TRACE_UPDATE_STATEMENT);
    my $delete_trace = $dbh->prepare($DELETE_TRACE_STATEMENT);

    my $ALARM_TIMEOUT = 3;
    my $last_data_received_time = time();
    local $SIG{ALRM} = sub {
        print $l "===ALARM===\n";
        my $elapsed = time() - $last_data_received_time;
        if ($elapsed > $ALARM_TIMEOUT) {
            print $l "GONNA SHUT IT ALLL DOWNNNNNNNNN\n";
            alarm 0;
            close $named_pipe_fh;
            $dbh->disconnect;

            exit;
        }

        alarm $ALARM_TIMEOUT;
    };

    alarm $ALARM_TIMEOUT;

    local $SIG{INT} = sub {
        while (<$named_pipe_fh>) {
            print $l "EXTRA!: $_\n";
            process_trace($_, $trace_insert, $end_trace_update, $delete_trace);
            $last_data_received_time = time();
        }
    };

    while (<$named_pipe_fh>) {
        process_trace($_, $trace_insert, $end_trace_update, $delete_trace);
        $last_data_received_time = time();
    }

    alarm 0;
    close $named_pipe_fh;
    $dbh->disconnect;

    exit;
}

sub process_trace {
    chomp(my $trace = $_[0]); $trace =~ s/\000//g;
    my $trace_insert = $_[1];
    my $end_trace_update = $_[2];
    my $delete_trace = $_[3];

    my @data = split /:/, $trace;

    if (scalar @data < $NUM_END_TRACE_COMPONENTS) {
        return;
    }

    my @query_data = ();
    if (scalar @data == $NUM_END_TRACE_COMPONENTS) {
        if ($data[$EXIT_STATUS] eq "killed") {
#            print $l "Deleting traces for killed PID $data[$PID_IDX]\n";
            print $l $trace . "\n\n";
            $delete_trace->execute($data[$PID_IDX]);
        } else {
#            print $l "Updating traces for PID $data[$PID_IDX] (status: $data[$EXIT_STATUS], input_size: $data[$INPUT_SIZE], suff: $data[7])\n";
            print $l $trace . "\n\n";
            $end_trace_update->execute(($data[$EXIT_STATUS], $data[$INPUT_SIZE], $data[$PID_IDX]));
        }
    } else {
        if (!$pids->{$data[$PID_IDX]}) {
            $pids->{$data[$PID_IDX]} = 1;
#            print $l "Processing trace for PID $data[$PID_IDX]\n";
            print $l $trace . "\n";
        }

        $query_data[$DB_EXPERIMENT_NAME] = $data[$EXPERIMENT_NAME];
        $query_data[$DB_SUBJECT] = $data[$SUBJECT];
        $query_data[$DB_BINARY_CONTEXT] = $data[$BINARY_CONTEXT];
        $query_data[$DB_EXEC_CONTEXT] = $data[$EXEC_CONTEXT];
        $query_data[$DB_PID_IDX] = $data[$PID_IDX];
        $query_data[$DB_EXIT_STATUS] = "unknown";
        $query_data[$DB_INPUT_SIZE] = 0;
        $query_data[$DB_FILENAME] = $data[$FILENAME];
        $query_data[$DB_FUNCTION_NAME] = $data[$FUNCTION_NAME];
        $query_data[$DB_VARIABLE_NAME] = $data[$VARIABLE_NAME];
        $query_data[$DB_DECLARED_LINE] = $data[$DECLARED_LINE];
        $query_data[$DB_MODIFIED_LINE] = $data[$MODIFIED_LINE];
        $query_data[$DB_TIMESTAMP] = $data[$TIMESTAMP];
        $query_data[$DB_VARIABLE_TYPE] = $data[$VARIABLE_TYPE];

        if (scalar @query_data > $NUM_TRACE_COMPONENTS) {
            $data[$VARIABLE_VALUE] = join ":", @data[$VARIABLE_VALUE, $#query_data];
        }

        $query_data[$DB_VARIABLE_VALUE] = $data[$VARIABLE_VALUE];
        $trace_insert->execute(@query_data);
    }
}

1;