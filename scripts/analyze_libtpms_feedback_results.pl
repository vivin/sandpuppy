#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';
use File::Path qw(make_path);
use Storable qw{lock_store lock_retrieve};

my $print_only;
if ($ARGV[0] && $ARGV[0] eq "print") {
   $print_only = 1;
} elsif ($ARGV[0]) {
    die "Usage: $0 [print]\n";
}

my $BASE_PATH = "/mnt/vivin-nfs";
if (! -d $BASE_PATH) {
    $BASE_PATH = "/media/2tb/phd-workspace/nfs";
}

my $RESULTS_DIR = "$BASE_PATH/vivin/smartdsf/libtpms/results";
my $OUTPUT_RESULTS_DIR = "$RESULTS_DIR/feedback";
make_path $OUTPUT_RESULTS_DIR;

my @runs = (
    "minus-vvhash",
    "minus-vvmax",
    "minus-vvmax2",
    "minus-vvperm",
    "only-vvhash",
    "only-vvmax",
    "only-vvmax2",
    "only-vvperm",
    "sp-original",
    "sp-random"
);

my $feedback_stats = {};
my $feedback_stats_filename = "$OUTPUT_RESULTS_DIR/feedback_stats-fullcmd.dat";
if ($print_only && ! -e -f $feedback_stats_filename) {
    die "Cannot print because saved stats file $feedback_stats_filename does not exist\n";
}

if (-e -f $feedback_stats_filename) {
    $feedback_stats = lock_retrieve $feedback_stats_filename;
} else {
    foreach my $run(@runs) {
        $feedback_stats->{$run} = {
            longest_command_sequence => 0,
            command_sequences        => {},
            unique_seq_length_counts => {},
            unique_subsequences      => {
                1 => {},
                2 => {},
                3 => {},
                4 => {}
            }
        }
    }
}

if ($print_only) {
    foreach my $run(keys %{$feedback_stats}) {
        output_run_stats($run);
    }
}

foreach my $run(@runs) {
    print "Processing libtpms feedback results for run $run...\n\n";

    my $run_dir = "$RESULTS_DIR/$run/sandpuppy-sync";
    next if ! -e -d $run_dir;

    chomp(my @sessions = `grep "^[^- ]" $RESULTS_DIR/$run/id_to_pod_name_and_target.yml | sed -e 's,:,,'`);

    my $num_sessions = scalar @sessions;
    my $i = 0;
    foreach my $session(@sessions) {
        my $dir = "$run_dir/$session/queue";
        next if ! -e -d $dir;

        print "[" . (++$i) . "/$num_sessions] Processing inputs in session $session...\n";

        chomp (my $num_files = `ls -f $dir | grep -v "^\\." | grep -v ",sync:" | wc -l`);
        my $count = 0;
        open FILES, "ls -f $dir |";
        while (my $file = <FILES>) {
            chomp $file;

            if ($file =~ /id:/ && $file !~ /,sync:/) {
                print "Processing input " . (++$count) . " of $num_files                   \r";
                process_commands_for_input("$dir/$file", $run);
            }
        }
        close FILES;

        lock_store $feedback_stats, $feedback_stats_filename;
    }

    print " " x 120 . "\n";
    output_run_stats($run);
}

sub output_run_stats {
    my $run = $_[0];

    my $longest_command_sequence_ref = \$feedback_stats->{$run}->{longest_command_sequence};
    my $command_sequences = $feedback_stats->{$run}->{command_sequences};
    my $unique_seq_length_counts = $feedback_stats->{$run}->{unique_seq_length_counts};
    my $unique_subsequences = $feedback_stats->{$run}->{unique_subsequences};

    open OUT, ">", "$OUTPUT_RESULTS_DIR/$run" . "-fullcmd.txt" if !$print_only;

    print "Results for run $run\n\n";
    print OUT "Results for run $run\n\n" if !$print_only;

    print "  Longest command sequence: $$longest_command_sequence_ref\n\n";
    print OUT "  Longest command sequence: $$longest_command_sequence_ref\n\n" if !$print_only;

    open UNIQUE_SEQ_COUNTS, ">", "$OUTPUT_RESULTS_DIR/$run-unique-seq-counts-fullcmd.dat" if !$print_only;
    my @unique_seq_counts = ();
    foreach my $sequence_length(sort { $a <=> $b } (keys %{$unique_seq_length_counts})) {
        print "  Unique command sequences of length $sequence_length: " . $unique_seq_length_counts->{$sequence_length} . "\n";
        print OUT "  Unique command sequences of length $sequence_length: " . $unique_seq_length_counts->{$sequence_length} . "\n" if !$print_only;
        push @unique_seq_counts, $unique_seq_length_counts->{$sequence_length};
    }
    print UNIQUE_SEQ_COUNTS "[" . (join ", ", @unique_seq_counts) . "]" if !$print_only;
    close UNIQUE_SEQ_COUNTS if !$print_only;

    print "\n";
    print OUT "\n" if !$print_only;

    print "  Unique full command sequences: " . scalar (keys %{$command_sequences}) . "\n\n";
    print OUT "  Unique full command sequences: " . scalar (keys %{$command_sequences}) . "\n\n" if !$print_only;
    foreach my $sequence_length(sort { $a <=> $b } (keys %{$unique_subsequences})) {
        print "  Unique command subsequences of length $sequence_length: " . scalar (keys %{$unique_subsequences->{$sequence_length}}) . "\n";
        print OUT "  Unique command subsequences of length $sequence_length: " . scalar (keys %{$unique_subsequences->{$sequence_length}}) . "\n" if !$print_only;
    }

    print "\n";

    if (!$print_only) {
        print OUT "\n";

        close OUT;
    }
}

sub process_commands_for_input {
    my $file = $_[0];
    my $run = $_[1];

    my $longest_command_sequence_ref = \$feedback_stats->{$run}->{longest_command_sequence};
    my $command_sequences = $feedback_stats->{$run}->{command_sequences};
    my $unique_seq_length_counts = $feedback_stats->{$run}->{unique_seq_length_counts};
    my $unique_subsequences = $feedback_stats->{$run}->{unique_subsequences};

    my $prev_line_is_startup = 0;
    my @commands = ();
    open CMDS, "/home/vivin/Projects/phd/resources/readtpmc-fullcmd $file |";
    while (my $line = <CMDS>) {
        chomp $line;
        if ($line =~ /__#CMD#__: /) {
            my $command = $line;
            $command =~ s/__#CMD#__: //;

            if ($prev_line_is_startup == 0) {
                push @commands, $command;
            }

            $prev_line_is_startup = 0;
        } elsif ($line =~ /__#STARTUP#__/) {
            $prev_line_is_startup = 1;
        }
    }
    close CMDS;

    my $command_seq_length = scalar @commands;
    my $command_seq = join ".", @commands;
    if (!$command_sequences->{$command_seq}) {
        $command_sequences->{$command_seq} = 1;

        if (!$unique_seq_length_counts->{$command_seq_length}) {
            $unique_seq_length_counts->{$command_seq_length} = 0;
        }

        $unique_seq_length_counts->{$command_seq_length}++;
    }

    # Extract sequences of length 1, 2, 3, and 4 respectively (as long as the sequences as long enough) to identify
    # unique ones.
    foreach my $seq_length(1, 2, 3, 4) {
        last if $command_seq_length < $seq_length;

        for(my $i = 0; $i <= $command_seq_length - $seq_length; $i++) {
            my @sequence = @commands[$i..($i + $seq_length - 1)];
            $unique_subsequences->{$seq_length}->{join ".", @sequence} = 1;
        }
    }

    if ($command_seq_length > $$longest_command_sequence_ref) {
        $$longest_command_sequence_ref = $command_seq_length;
    }
}