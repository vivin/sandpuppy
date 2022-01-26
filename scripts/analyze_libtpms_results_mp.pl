#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';
use Parallel::ForkManager;

if (scalar @ARGV < 1) {
    die "Usage: $0 sandpuppy | aflplusplus-(plain | lafintel | redqueen)\n";
}

my %edges = ();
my %command_edges = ();
my %command_sequences = ();
my %seq_length_counts = ();
my %unique_sequences = (
    1 => {},
    2 => {},
    3 => {},
    4 => {}
);
my $longest_execution_path = 0;
my $longest_command_sequence = 0;

my $num_files;

my @files = ();
my $fuzzer = $ARGV[0];
if ($fuzzer eq "sandpuppy") {
    print "Analyzing results for sandpuppy...\n";

    $num_files = 822563;
    open DIRS, "find /mnt/vivin-nfs/vivin/libtpms_results/sandpuppy-sync -maxdepth 1 -mindepth 1 -type d |";
    while (my $dir = <DIRS>) {
        chomp $dir;

        my $dir_only = $dir;
        $dir_only =~ s,^.*/,,;

        print "Gathering inputs from target $dir_only\n";
        open FILES, "ls -f $dir/queue |";
        while (my $file = <FILES>) {
            chomp $file;

            if ($file =~ /id:/ && $file !~ /,sync:/) {
                push @files, "$dir/queue/$file";
            }
        }
        close FILES;

        print "\n";
    }
    close DIRS;

} elsif ($fuzzer =~ /^aflplusplus-/) {
    print "Analyzing results for $fuzzer...\n";
    my $dir = "/mnt/vivin-nfs/vivin/libtpms_results/$fuzzer/default/queue";
    chomp ($num_files = `ls -f $dir | grep -v "^\\." | wc -l`);

    open FILES, "ls -f $dir |";
    while (my $file = <FILES>) {
        chomp $file;

        if ($file =~ /id:/ && $file !~ /,sync:/) {
            push @files, "$dir/$file";
        }
    }
    close FILES;

    print "\n";
}

my @results = ();
my $pm = Parallel::ForkManager->new(12, '/tmp/pfm');
my $count = 0;
$pm->run_on_finish (
    sub {
        my ($pid, $exit_code, $ident, $exit_signal, $core_dump, $data) = @_;
        print "Finished processing file " . (++$count) . " of $num_files\r";
        push @results, $data;
    }
);

FILES:
foreach my $file(@files) {
    $pm->start and next FILES;
    my $data = get_basic_blocks_and_commands_for_input($file);
    $pm->finish(0, $data);
}
$pm->wait_all_children;

print "\n";

$count = 0;
foreach my $data(@results) {
    print "Processing " . (++$count) . " of $num_files\n";
    my $output = $data->{output};
    my @lines = split /\n/, $output;
    my @basic_blocks = ();
    my @commands = ();
    foreach my $line(@lines) {
        chomp $line;
        if ($line =~ /__#BB#__: /) {
            my $basic_block = $line;
            $basic_block =~ s/__#BB#__: //;
            push @basic_blocks, $basic_block;
        } elsif ($line =~ /__#CMD#__: /) {
            my $command = $line;
            $command =~ s/__#CMD#__: //;
            push @commands, $command;
        }
    }

    #my @basic_blocks = @{$data->{basic_blocks}};
    #my @commands = @{$data->{commands}};

    #my $previous_basic_block = "NONE";
    #foreach my $basic_block(@basic_blocks) {
    #    if ($previous_basic_block ne "NONE") {
    #        $edges{"\"$previous_basic_block\" -> \"$basic_block\""} = 1;
    #    }
    #
    #    $previous_basic_block = $basic_block;
    #}

    if (scalar @basic_blocks > $longest_execution_path) {
        $longest_execution_path = scalar @basic_blocks;
    }

    my $previous_command = "START";
    foreach my $command(@commands) {
        $command_edges{"\"$previous_command\" -> \"$command\""} = 1;
        $previous_command = $command;
    }

    $command_sequences{join ".", @commands} = 1;
    if (!$seq_length_counts{scalar @commands}) {
        $seq_length_counts{scalar @commands} = 0;
    }

    $seq_length_counts{scalar @commands}++;

    # Extract sequences of length 1, 2, 3, and 4 respectively (as long as the sequences as long enough) to identify
    # unique ones.
    foreach my $seq_length(1, 2, 3, 4) {
        last if scalar @commands < $seq_length;

        for(my $i = 0; $i <= scalar @commands - $seq_length; $i++) {
            my @sequence = @commands[$i..($i + $seq_length - 1)];
            $unique_sequences{$seq_length}->{join ".", @sequence} = 1;
        }
    }

    if (scalar @commands > $longest_command_sequence) {
        $longest_command_sequence = scalar @commands;
    }
}

print "Longest execution path:$longest_execution_path\n";
print "Longest command sequence: $longest_command_sequence\n";
foreach my $sequence_length(sort { $a <=> $b } (keys %seq_length_counts)) {
    print "Command sequences of length $sequence_length: " . $seq_length_counts{$sequence_length} . "\n";
}

print "Unique full command sequences: " . scalar (keys %command_sequences) . "\n";
foreach my $sequence_length(sort { $a <=> $b } (keys %unique_sequences)) {
    print "Unique command sequences of length $sequence_length: " . scalar (keys %{$unique_sequences{$sequence_length}}) . "\n";
}

print "Creating graphviz file ($fuzzer.dot)...";
open GRAPHVIZ, ">", "$fuzzer.dot";
print GRAPHVIZ "digraph state_graph {\n";
foreach my $edge(keys %command_edges) {
    print GRAPHVIZ "  $edge\n";
}
print GRAPHVIZ "}\n";
close GRAPHVIZ;
print "done\n";

sub get_basic_blocks_and_commands_for_input {
    my $file = $_[0];
    my $output = `/home/vivin/Projects/phd/workspace/smartdsf/libtpms/binaries/print-states/readtpmc $file`;
    return {
        output => $output
    };
}