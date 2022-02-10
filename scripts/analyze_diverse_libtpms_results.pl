#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';
use File::Path qw(make_path);
use Storable;

my $print;
if ($ARGV[0] && $ARGV[0] eq "print") {
   $print = 1;
} elsif ($ARGV[0]) {
    die "Usage: $0 sandpuppy | afl-plain | aflplusplus-(plain | lafintel | redqueen)\n";
}

my $STATE_DIR = glob "~/.script-state/$0";
make_path $STATE_DIR;

my $BASE_PATH = "/mnt/vivin-nfs";
if (! -d $BASE_PATH) {
    $BASE_PATH = "/media/2tb/phd-workspace/nfs";
}

my $RUN_DIR = "$BASE_PATH/vivin/smartdsf/libtpms/results/di-ec-run";

my @fuzzers = ("afl-plain", "aflplusplus-plain", "aflplusplus-lafintel", "aflplusplus-redqueen", "sandpuppy");

my $fuzzer_stats = {};
my $fuzzer_stats_filename = "$RUN_DIR/fuzzer_stats.dat";
if (-e -f $fuzzer_stats_filename) {
    $fuzzer_stats = retrieve $fuzzer_stats_filename;
} else {
    foreach my $fuzzer(@fuzzers) {
        $fuzzer_stats->{$fuzzer} = {
            longest_command_sequence => 0,
            command_edges            => [],
            command_sequences        => [],
            seq_length_counts        => [],
            unique_seq_length_counts => [],
            unique_subsequences      => {
                1 => {},
                2 => {},
                3 => {},
                4 => {}
            }
        }
    }
}

foreach my $fuzzer(@fuzzers) {
    print "Processing libtpms results for fuzzer $fuzzer...\n\n";

    make_path "$RUN_DIR/aggregated";

    my $fuzzer_dir = "$RUN_DIR/$fuzzer-sync";
    next if ! -e -d $fuzzer_dir;

    my @sessions;
    if ($fuzzer ne "sandpuppy") {
        my $sync_prefix = $fuzzer;
        if ($fuzzer eq "aflplusplus-lafintel") {
            $sync_prefix = "aflplusplus-lafi";
        } elsif ($fuzzer eq "aflplusplus-redqueen") {
            $sync_prefix = "aflplusplus-redq";
        }

        @sessions = ("$sync_prefix-main");
        push @sessions, map { "$sync_prefix-c$_" } (1..48);

    } else {
        chomp(@sessions = `grep "^[^- ]" $RUN_DIR/id_to_pod_name_and_target.yml | sed -e 's,:,,'`);
    }

    my $num_sessions = scalar @sessions;
    my $i = 0;
    foreach my $session(@sessions) {
        my $dir = "$fuzzer_dir/$session/queue";
        next if ! -e -d $dir;

        print "[$i/$num_sessions] Processing inputs in session $session...\b";

        chomp (my $num_files = `ls -f $dir | grep -v "^\\." | grep -v ",sync:" | wc -l`);
        my $count = 0;
        open FILES, "ls -f $dir |";
        while (my $file = <FILES>) {
            chomp $file;

            my $state_file = "$STATE_DIR/$session-$file";
            if (-e $state_file) {
                print "Skipping input " . (++$count) . " of $num_files (already processed)\r";
            } elsif ($file =~ /id:/ && $file !~ /,sync:/) {
                print "Processing input " . (++$count) . " of $num_files                   \r";
                process_commands_for_input("$dir/$file");
                system "touch $state_file";
            }
        }
        close FILES;

        store $fuzzer_stats, $fuzzer_stats_filename;

        $i++;
    }

    output_fuzzer_stats($fuzzer);
}

sub output_fuzzer_stats {
    my $fuzzer = $_[0];

    my $longest_command_sequence_ref = \$fuzzer_stats->{$fuzzer}->{longest_command_sequence};
    my $command_edges = $fuzzer_stats->{$fuzzer}->{command_edges};
    my $command_sequences = $fuzzer_stats->{$fuzzer}->{command_sequences};
    my $seq_length_counts = $fuzzer_stats->{$fuzzer}->{seq_length_counts};
    my $unique_seq_length_counts = $fuzzer_stats->{$fuzzer}->{unique_seq_length_counts};
    my $unique_subsequences = $fuzzer_stats->{$fuzzer}->{unique_subsequences};

    open OUT, ">", "$RUN_DIR/aggregated/$fuzzer.txt";

    print "Longest command sequence: $$longest_command_sequence_ref\n";
    print OUT "Longest command sequence: $$longest_command_sequence_ref\n";
    foreach my $sequence_length(sort { $a <=> $b } (keys %{$seq_length_counts})) {
        print "Command sequences of length $sequence_length: " . $seq_length_counts->{$sequence_length} . "\n";
        print OUT "Command sequences of length $sequence_length: " . $seq_length_counts->{$sequence_length} . "\n";
    }

    open UNIQUE_SEQ_COUNTS, ">", "$RUN_DIR/aggregated/$fuzzer-unique-seq-counts.dat";
    my @unique_seq_counts = ();
    foreach my $sequence_length(sort { $a <=> $b } (keys %{$unique_seq_length_counts})) {
        print "Unique command sequences of length $sequence_length: " . $unique_seq_length_counts->{$sequence_length} . "\n";
        print OUT "Unique command sequences of length $sequence_length: " . $unique_seq_length_counts->{$sequence_length} . "\n";
        push @unique_seq_counts, $unique_seq_length_counts->{$sequence_length};
    }
    print UNIQUE_SEQ_COUNTS "[" . (join ", ", @unique_seq_counts) . "]";
    close UNIQUE_SEQ_COUNTS;

    print "Unique full command sequences: " . scalar (keys %{$command_sequences}) . "\n";
    print OUT "Unique full command sequences: " . scalar (keys %{$command_sequences}) . "\n";
    foreach my $sequence_length(sort { $a <=> $b } (keys %{$unique_subsequences})) {
        print "Unique command subsequences of length $sequence_length: " . scalar (keys %{$unique_subsequences->{$sequence_length}}) . "\n";
        print OUT "Unique command subsequences of length $sequence_length: " . scalar (keys %{$unique_subsequences->{$sequence_length}}) . "\n";
    }

    close OUT;

    print "Creating graphviz file ($fuzzer.dot)...";
    open GRAPHVIZ, ">", "$RUN_DIR/aggregated/$fuzzer.dot";
    print GRAPHVIZ "digraph state_graph {\n";
    foreach my $edge(keys %{$command_edges}) {
        print GRAPHVIZ "  $edge\n";
    }
    print GRAPHVIZ "}\n";
    close GRAPHVIZ;
    print "done\n";

    print "Generating PS file out of graphviz file...";
    system "dot -Tps $BASE_PATH/vivin/smartdsf/libtpms/aggregated/$fuzzer.dot -o $BASE_PATH/vivin/smartdsf/libtpms/aggregated/$fuzzer.ps";
    print "done\n";

    print "Generating PNG file out of graphviz file...";
    system "dot -Tpng $BASE_PATH/vivin/smartdsf/libtpms/aggregated/$fuzzer.dot -o $BASE_PATH/vivin/smartdsf/libtpms/aggregated/$fuzzer.png";
    print "done\n";
}

sub process_commands_for_input {
    my $file = $_[0];
    my $fuzzer = $_[1];

    my $longest_command_sequence_ref = \$fuzzer_stats->{$fuzzer}->{longest_command_sequence};
    my $command_edges = $fuzzer_stats->{$fuzzer}->{command_edges};
    my $command_sequences = $fuzzer_stats->{$fuzzer}->{command_sequences};
    my $seq_length_counts = $fuzzer_stats->{$fuzzer}->{seq_length_counts};
    my $unique_seq_length_counts = $fuzzer_stats->{$fuzzer}->{unique_seq_length_counts};
    my $unique_subsequences = $fuzzer_stats->{$fuzzer}->{unique_subsequences};

    my $prev_line_is_startup = 0;
    my @commands = ();
    open CMDS, "/home/vivin/Projects/phd/resources/readtpmc $file |";
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

    my $previous_command = "START";
    foreach my $command(@commands) {
        $command_edges->{"\"$previous_command\" -> \"$command\""} = 1;
        $previous_command = $command;
    }

    my $command_seq_length = scalar @commands;
    my $command_seq = join ".", @commands;
    if (!$command_sequences->{$command_seq}) {
        $command_sequences->{$command_seq} = 1;

        if (!$unique_seq_length_counts->{$command_seq_length}) {
            $unique_seq_length_counts->{$command_seq_length} = 0;
        }

        $unique_seq_length_counts->{$command_seq_length}++;
    }

    if (!$seq_length_counts->{$command_seq_length}) {
        $seq_length_counts->{$command_seq_length} = 0;
    }

    $seq_length_counts->{$command_seq_length}++;

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