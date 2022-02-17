#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';
use File::Path qw(make_path);
use Storable qw{lock_store lock_retrieve};
use POSIX qw{floor};
use Statistics::Lite qw(mean);

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
my $fuzzer_stats_filename = "$RESULTS_DIR/fuzzer_stats-lengths.dat";
if ($print_only && ! -e -f $fuzzer_stats_filename) {
    die "Cannot print because saved stats file $fuzzer_stats_filename does not exist\n";
}

if (-e -f $fuzzer_stats_filename) {
    $fuzzer_stats = lock_retrieve $fuzzer_stats_filename;
} else {
    foreach my $fuzzer(@fuzzers) {
        $fuzzer_stats->{$fuzzer} = {
            command_sequence_lengths_over_time => {},
            unique_sequences_found_over_time   => {},
            command_sequences                  => {}
        };

        foreach my $hour(0..120) {
            $fuzzer_stats->{$fuzzer}->{command_sequence_lengths_over_time}->{$hour} = [];
            $fuzzer_stats->{$fuzzer}->{unique_sequences_found_over_time}->{$hour} = 0;
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

        chomp(my $first_input = `find $dir -maxdepth 1 -mindepth 1 -name "id:000000,*"`);
        chomp(my $start_time = `stat -c '%Y' "$first_input"`);

        chomp (my $num_files = `ls -f $dir | grep -v "^\\." | grep -v ",sync:" | wc -l`);
        my $count = 0;
        open FILES, "ls -f $dir |";
        while (my $file = <FILES>) {
            chomp $file;

            if ($file =~ /id:/ && $file !~ /,sync:/) {
                print "Processing input " . (++$count) . " of $num_files                   \r";
                process_commands_for_input("$dir/$file", $fuzzer, $start_time);
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

    my $command_sequence_lengths_over_time = $fuzzer_stats->{$fuzzer}->{command_sequence_lengths_over_time};
    my @average_command_sequence_lengths_over_time = map {
        scalar @{$command_sequence_lengths_over_time->{$_}} > 0 ? mean @{$command_sequence_lengths_over_time->{$_}} : 0
    } (0..120);
    my @unique_sequences_found_over_time = map { $fuzzer_stats->{$fuzzer}->{unique_sequences_found_over_time}->{$_} } (0..120);

    open OUT, ">", "$RESULTS_DIR/$fuzzer" . "-lengths.txt" if !$print_only;

    print "Results for fuzzer $fuzzer\n\n";
    print OUT "Results for fuzzer $fuzzer\n\n" if !$print_only;

    print "  Average command sequence lengths over time: [" . (join ", ", @average_command_sequence_lengths_over_time) . "]\n";
    print OUT "  Average command sequence lengths over time: [" . (join ", ", @average_command_sequence_lengths_over_time) . "]\n" if !$print_only;
    print "  Unique sequences found over time: [" . (join ", ", @unique_sequences_found_over_time) . "]\n\n";
    print OUT "  Unique sequences found over time: [" . (join ", ", @unique_sequences_found_over_time) . "]\n\n" if !$print_only;
}

sub process_commands_for_input {
    my $file = $_[0];
    my $fuzzer = $_[1];
    my $start_time = $_[2];

    chomp(my $input_found_time = `stat -c '%Y' "$file"`);
    my $hour = floor (($input_found_time - $start_time) / (60 * 60));

    my $command_sequences = $fuzzer_stats->{$fuzzer}->{command_sequences};
    my $command_sequence_lengths_for_hour = $fuzzer_stats->{$fuzzer}->{command_sequence_lengths_over_time}->{$hour};

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
    push @{$command_sequence_lengths_for_hour}, $command_seq_length;

    my $command_seq = join ".", @commands;
    if (!$command_sequences->{$command_seq}) {
        $fuzzer_stats->{$fuzzer}->{unique_sequences_found_over_time}->{$hour}++;

        $command_sequences->{$command_seq} = 1;
    }
}