#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';
use File::Path qw(make_path);
use File::Basename;
use List::Util qw(sum);

if (!$ARGV[0]) {
    print "$0 <run-name>\n";
    exit 1;
}

my $RUN_NAME = $ARGV[0];
my $SCRIPT_NAME = basename $0;
my $BASE_PATH = "/mnt/vivin-nfs";
if (! -d $BASE_PATH) {
    $BASE_PATH = "/media/2tb/phd-workspace/nfs";
}

my $RUN_DIR = "$BASE_PATH/vivin/smartdsf/jsoncpp/results/$RUN_NAME";
if (! -d $RUN_DIR) {
    print "Cannot find run directory $RUN_DIR\n";
    exit 1;
}

my $RESULTS_DIR = "$RUN_DIR/aggregated";
make_path $RESULTS_DIR;

open BBS, '<', "resources/jsoncpp-basic-blocks.txt";
chomp(my @basic_blocks = <BBS>);
close BBS;

my $total_basic_blocks = scalar @basic_blocks;

my @fuzzers = ("afl-plain", "aflplusplus-plain", "aflplusplus-lafintel", "aflplusplus-redqueen");
foreach my $fuzzer(@fuzzers) {
    my $basic_blocks_hit = {};

    print "Processing jsoncpp results for fuzzer $fuzzer...\n\n";

    my $fuzzer_dir = "$RUN_DIR/$fuzzer-sync";
    next if ! -e -d $fuzzer_dir;

    my $sync_prefix = $fuzzer;
    if ($fuzzer eq "aflplusplus-lafintel") {
        $sync_prefix = "aflplusplus-lafi";
    } elsif ($fuzzer eq "aflplusplus-redqueen") {
        $sync_prefix = "aflplusplus-redq";
    }

    my @sessions = ("$sync_prefix-main");
    push @sessions, map { "$sync_prefix-c$_" } (1..11);

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
                analyze_jsoncpp_coverage("$dir/$file", $basic_blocks_hit);
            }
        }
        close FILES;
    }

    my $blocks_hit = sum(map { defined $basic_blocks_hit->{$_} ? 1 : 0 } @basic_blocks);

    open BB_STATS, ">>", "$RESULTS_DIR/other-fuzzers-coverage-stats.txt";
    print "$fuzzer: $blocks_hit / $total_basic_blocks (" . ($blocks_hit / $total_basic_blocks) . ")\n";
    print BB_STATS "$fuzzer: $blocks_hit / $total_basic_blocks (" . ($blocks_hit / $total_basic_blocks) . ")\n";
    close BB_STATS;

    open BBS_HIT, ">", "$RESULTS_DIR/$fuzzer-basic-blocks-hit.txt";
    foreach my $bb(sort(keys(%{$basic_blocks_hit}))) {
        print BBS_HIT "$bb: $basic_blocks_hit->{$bb}\n";
    }
    close BBS_HIT;
}

sub analyze_jsoncpp_coverage {
    my $file = $_[0];
    my $basic_blocks_hit = $_[1];

    open BB, "resources/readjson-bbprinter $file 2> /dev/null | grep \"__#BB#__\" | grep -v readjson |";
    while (my $line = <BB>) {
        chomp $line;
        $line =~ s/__#BB#__: //;

        if (!$basic_blocks_hit->{$line}) {
            $basic_blocks_hit->{$line} = 0;
        }

        $basic_blocks_hit->{$line}++;
    }
    close BB;
}