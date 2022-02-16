#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';
use File::Path qw(make_path);
use Storable qw{lock_store lock_retrieve};

my $print_only;
if ($ARGV[0] && $ARGV[0] eq "print") {
   $print_only = 1;
} elsif ($ARGV[0]) {
    die "Usage: $0 sandpuppy | afl-plain | aflplusplus-(plain | lafintel | redqueen)\n";
}

my $BASE_PATH = "/mnt/vivin-nfs";
if (! -d $BASE_PATH) {
    $BASE_PATH = "/media/2tb/phd-workspace/nfs";
}

my $RUN_DIR = "$BASE_PATH/vivin/smartdsf/libtpms/results/di-ec-run";
my $RESULTS_DIR = "$RUN_DIR/aggregated";
make_path $RESULTS_DIR;

my @fuzzers = ("afl-plain", "aflplusplus-plain", "aflplusplus-lafintel", "aflplusplus-redqueen", "sandpuppy");

my $fuzzer_stats = {};
my $fuzzer_stats_filename = "$RESULTS_DIR/fuzzer_stats-fullcmd.dat";
if ($print_only && ! -e -f $fuzzer_stats_filename) {
    die "Cannot print because saved stats file $fuzzer_stats_filename does not exist\n";
}

if (-e -f $fuzzer_stats_filename) {
    $fuzzer_stats = lock_retrieve $fuzzer_stats_filename;
} else {
    foreach my $fuzzer(@fuzzers) {
        $fuzzer_stats->{$fuzzer} = {
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
    foreach my $fuzzer(keys %{$fuzzer_stats}) {
        output_fuzzer_stats($fuzzer);
    }
}

foreach my $fuzzer(@fuzzers) {
    print "Processing libtpms results for fuzzer $fuzzer...\n\n";

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

        print "[" . (++$i) . "/$num_sessions] Processing inputs in session $session...\n";

        chomp (my $num_files = `ls -f $dir | grep -v "^\\." | grep -v ",sync:" | wc -l`);
        my $count = 0;
        open FILES, "ls -f $dir |";
        while (my $file = <FILES>) {
            chomp $file;

            if ($file =~ /id:/ && $file !~ /,sync:/) {
                print "Processing input " . (++$count) . " of $num_files                   \r";
                process_commands_for_input("$dir/$file", $fuzzer);
            }
        }
        close FILES;

        lock_store $fuzzer_stats, $fuzzer_stats_filename;
    }

    print " " x 120 . "\n";
    output_fuzzer_stats($fuzzer);
}

sub output_fuzzer_stats {
    my $fuzzer = $_[0];

    my $longest_command_sequence_ref = \$fuzzer_stats->{$fuzzer}->{longest_command_sequence};
    my $command_sequences = $fuzzer_stats->{$fuzzer}->{command_sequences};
    my $unique_seq_length_counts = $fuzzer_stats->{$fuzzer}->{unique_seq_length_counts};
    my $unique_subsequences = $fuzzer_stats->{$fuzzer}->{unique_subsequences};

    open OUT, ">", "$RESULTS_DIR/$fuzzer" . "-fullcmd.txt" if !$print_only;

    print "Results for fuzzer $fuzzer\n\n";
    print OUT "Results for fuzzer $fuzzer\n\n" if !$print_only;

    print "  Longest command sequence: $$longest_command_sequence_ref\n\n";
    print OUT "  Longest command sequence: $$longest_command_sequence_ref\n\n" if !$print_only;

    open UNIQUE_SEQ_COUNTS, ">", "$RESULTS_DIR/$fuzzer-unique-seq-counts-fullcmd.dat" if !$print_only;
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
    my $fuzzer = $_[1];

    my $longest_command_sequence_ref = \$fuzzer_stats->{$fuzzer}->{longest_command_sequence};
    my $command_sequences = $fuzzer_stats->{$fuzzer}->{command_sequences};
    my $unique_seq_length_counts = $fuzzer_stats->{$fuzzer}->{unique_seq_length_counts};
    my $unique_subsequences = $fuzzer_stats->{$fuzzer}->{unique_subsequences};

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