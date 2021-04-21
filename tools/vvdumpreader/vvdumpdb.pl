use strict;
use warnings FATAL => 'all';
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

my $TRACE_INSERT_STATEMENT = "INSERT INTO vvdump VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
my $END_TRACE_UPDATE_STATEMENT = "UPDATE vvdump SET exit_status = ? WHERE pid = ?";
my $DELETE_TRACE_STATEMENT = "DELETE FROM vvdump WHERE exit_status = 'unknown' AND pid = ?";

    my $dbh = DBI->connect(
        "dbi:Pg:dbname=$db;host=$host;port=$port",
        $username,
        $password,
        { AutoCommit => 1, RaiseError => -1}
    ) or die $DBI::errstr;

    my $trace_insert = $dbh->prepare($TRACE_INSERT_STATEMENT);
    my $end_trace_update = $dbh->prepare($END_TRACE_UPDATE_STATEMENT);
    my $delete_trace = $dbh->prepare($DELETE_TRACE_STATEMENT);

    if (! -e $NAMED_PIPE_PATH) {
        mkfifo($NAMED_PIPE_PATH, 0700) or die "Could not create named pipe at $NAMED_PIPE_PATH: $!";
    }

    # pipe opened in rw mode so that it remains open even after we have read stuff
    my $named_pipe_fh;
    open $named_pipe_fh, "+<", $NAMED_PIPE_PATH or die "Could not open named pipe at $NAMED_PIPE_PATH: $!";

    $log->info("Opened named pipe at $NAMED_PIPE_PATH. Waiting for data...");

    while (<$named_pipe_fh>) {
        $_ =~ s/\000//g;
        print;
        my @data = split /:/;

        if (scalar @data < $NUM_END_TRACE_COMPONENTS) {
            next;
        }

        my @query_data = ();
        if (scalar @data == $NUM_END_TRACE_COMPONENTS) {
            if ($data[$EXIT_STATUS] eq "killed") {
                $delete_trace->execute($data[$PID_IDX]);
            } else {
                $end_trace_update->execute(($data[$EXIT_STATUS], $data[$PID_IDX]));
            }
        } else {
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

        #print "Received: $_";
    }

    close $named_pipe_fh;
    $dbh->disconnect;
