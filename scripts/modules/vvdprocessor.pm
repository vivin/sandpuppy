package vvdprocessor;

use strict;
use warnings FATAL => 'all';
use POSIX qw(mkfifo);

use Log::Simple::Color;
use Log::Log4perl;

use DBI;
use Parallel::ForkManager;
use Parallel::ForkManager::Scaled;
use Time::HiRes qw(usleep);

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

my $QUEUE_POISON_PILL = "END";
my $NAMED_PIPE_POISON_PILL = '__$VVDUMP_END$__';

my $log = Log::Simple::Color->new;

my $pids = {};

Log::Log4perl::init(glob "~/.config/log4perl/log4perl.conf");

my $TRACE_INSERT_STATEMENT = "INSERT INTO vvdump VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
my $DEFERRED_TRACE_INSERT_STATEMENT = "INSERT INTO deferred_traces VALUES (?)";
my $END_TRACE_UPDATE_STATEMENT = "UPDATE vvdump SET exit_status = ?, input_size = ? WHERE pid = ? AND exit_status = 'unknown'";
my $DELETE_TRACE_STATEMENT = "DELETE FROM vvdump WHERE exit_status = 'unknown' AND pid = ?";

# TODO: so here's the deal. if you have your instrumented stuff write to a named pipe in blocking mode, and also have
# TODO: afl-fuzz write to it in blocking mode, then you can generally get all the vvdump traces you need. however
# TODO: fuzzing performance is EXTREMELY SLOW compared to non-blocking. The problem with non-blocking is that you end
# TODO: up losing data because the reader can't read and process it as fast as we want it to. the bottleneck is when it
# TODO: needs to write to the database. that takes too long and we end up losing data in the meantime. i have tried to
# TODO: run the code that inserts into the database in separate processes but that doesn't seem to be working either.
# TODO: it just can't keep up. the updates and deletes are what take the most time. i will try doing inserts on the same
# TODO: thread and updates on another. OK that isn't working either. so let's try something else. we will just write out
# TODO: all the "killed" and "end" lines into a file. and then once we are done with everything else, we will process
# TODO: them at the end. OK doing that didn't work either. it's just too slow i think. i think the poison pill doesn't
# TODO: get read at all because it probably gets lost as the pipe is too full. maybe we just have to do it in blocking
# TODO: mode and take the performance hit. really what i need is a secondary caching mechanism. what the hell could it
# TODO: be? the stuff with the shared queue almost works... ugh. maybe one option is to ignore all pointer type vars?
# TODO: we could do that initially. that would cut down on data. but i am so sure there is a way to make this performant

sub start {
    my $logger = Log::Log4perl->get_logger("vvdprocessor.start");
    if (! -e $NAMED_PIPE_PATH) {
        mkfifo($NAMED_PIPE_PATH, 0700) or die "Could not create named pipe at $NAMED_PIPE_PATH: $!";
    }

    my $reader_pid = reader();

    $logger->info("Created reader $reader_pid");

    return $reader_pid;
}

sub reader {
    my $reader_pid = fork;
    return $reader_pid if $reader_pid;

    local $SIG{INT} = 'IGNORE';

    my $logger = Log::Log4perl->get_logger("vvdprocessor.reader");

    $log->info("Started child process to read data from named pipe at $NAMED_PIPE_PATH");
    open my $named_pipe_fh, "+<", $NAMED_PIPE_PATH or die "Could not open named pipe at $NAMED_PIPE_PATH: $!";
    $log->info("Opened pipe successfully...");

    my $dbh = DBI->connect(
        "dbi:Pg:dbname=$db;host=$host;port=$port",
        $username,
        $password,
        { AutoCommit => 1, RaiseError => 0, PrintError => 0 }
    ) or die $DBI::errstr;

    # prepare cached so that when subprocesses prepare them they don't conflict
    $dbh->prepare_cached($TRACE_INSERT_STATEMENT);
    $dbh->prepare_cached($DEFERRED_TRACE_INSERT_STATEMENT);
    $dbh->prepare_cached($END_TRACE_UPDATE_STATEMENT);
    $dbh->prepare_cached($DELETE_TRACE_STATEMENT);

    my $pm = Parallel::ForkManager->new(64); # for scaled: (initial_procs => 48);
    #$pm->hard_max_procs(48);
    #$pm->hard_min_procs(16);

    $pm->run_on_finish(
        sub {
            my ($child_pid, $exit_code, $ident, $exit_signal, $core_dump, $data) = @_;
            if (defined $data) {
                my ($trace_type, $pid, $trace) = @{$data};

                if ($trace_type eq "vvdump" and !$pids->{$pid}) {
                    $pids->{$pid} = 1;

                    $logger->info("Inserted: $trace");
                } elsif ($trace_type ne "vvdump") {
                    $logger->info("Deferred: $trace");
                }
            }
        }
    );

    my $i = 0;

    TRACES:
    while (<$named_pipe_fh>) {
        chomp;
        $_ =~ s/\000//g;
        if ($_ eq $NAMED_PIPE_POISON_PILL) {
            $logger->info("got named pipe poison pill");
            last;
        }

        $i++;

        $pm->start and next TRACES;

        local $SIG{INT} = 'IGNORE';
        my $child_dbh = $dbh->clone;
        $dbh->{InactiveDestroy} = 1;
        undef $dbh;

        my @response = process_trace($_, $child_dbh, $i);

        $pm->finish(0, \@response);
    }

    $pm->wait_all_children;

    $dbh->disconnect;
    close $named_pipe_fh;

    exit;
}

sub process_trace {

    my $logger = Log::Log4perl->get_logger("vvdprocessor.process_trace");

    my $trace = $_[0];
    my $dbh = $_[1];
    my $i = $_[2];

    if (($i % 1000) eq 0) {
        $logger->info("Inserting: $trace");
    }

    my @data = split /:/, $trace;

    if (scalar @data < $NUM_END_TRACE_COMPONENTS) {
        return;
    }

    my @query_data = ();
    if (scalar @data == $NUM_END_TRACE_COMPONENTS) {

       # if ($data[$EXIT_STATUS] eq "killed") {
            #$logger->info("Deleting traces for killed PID $data[$PID_IDX]");

            #my $delete_trace = $dbh->prepare($DELETE_TRACE_STATEMENT);
            #$delete_trace->execute($data[$PID_IDX]);
       # } else {
           # $logger->info("Updating traces for PID $data[$PID_IDX] (status: $data[$EXIT_STATUS], input_size: $data[$INPUT_SIZE])");

           # fork {
           #     sub  => sub {
           #         local $SIG{INT} = 'IGNORE';
           #         my $parent_dbh = $_[0];
           #         my $child_dbh = $parent_dbh->clone;
           #         $parent_dbh->{InactiveDestroy} = 1;
           #         undef $parent_dbh;

            #        my $data = $_[1];
            #        my $end_trace_update = $child_dbh->prepare($END_TRACE_UPDATE_STATEMENT);
            #        $end_trace_update->execute(($data->[$EXIT_STATUS], $data->[$INPUT_SIZE], $data->[$PID_IDX]));
            #    },
            #    args => [($dbh, \@data)]
            #};
       # }

        my $deferred_trace_insert = $dbh->prepare_cached($DEFERRED_TRACE_INSERT_STATEMENT);
        $deferred_trace_insert->execute(($trace));

        return ($data[$EXIT_STATUS] eq "killed" ? "killed" : "end", $data[$PID_IDX], $trace);
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

        my $trace_insert = $dbh->prepare_cached($TRACE_INSERT_STATEMENT);
        $trace_insert->execute(@query_data);

        return ("vvdump", $data[$PID_IDX], $trace);
    }
}

1;