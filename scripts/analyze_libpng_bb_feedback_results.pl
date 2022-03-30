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
    die "Usage: $0 [print]\n";
}

my $BASE_PATH = "/mnt/vivin-nfs";
if (! -d $BASE_PATH) {
    $BASE_PATH = "/media/2tb/phd-workspace/nfs";
}

my $RESULTS_DIR = "$BASE_PATH/vivin/smartdsf/libpng-1.5.9/results";
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
my $feedback_stats_filename = "$OUTPUT_RESULTS_DIR/feedback_bb_stats.dat";
if ($print_only && ! -e -f $feedback_stats_filename) {
    die "Cannot print because saved stats file $feedback_stats_filename does not exist\n";
}

if (-e -f $feedback_stats_filename) {
    $feedback_stats = lock_retrieve $feedback_stats_filename;
} else {
    foreach my $run(@runs) {
        $feedback_stats->{$run} = {
            basic_blocks_hit => {},
            coverage         => 0
        };
    }
}

if ($print_only) {
    foreach my $run(keys %{$feedback_stats}) {
        output_run_stats($run);
    }
}

chomp(my $total_basic_blocks = `cat resources/libpng-basic-blocks.txt | wc -l`);
foreach my $run(@runs) {
    print "Processing libpng feedback results for run $run...\n\n";

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
                process_stats_for_input_image("$dir/$file", $run);
            }
        }
        close FILES;

        lock_store $feedback_stats, $feedback_stats_filename;
    }

    $feedback_stats->{$run}->{coverage} = (scalar keys %{$feedback_stats->{$run}->{basic_blocks_hit}}) / $total_basic_blocks;

    print " " x 120 . "\n";
    output_run_stats($run);
}

sub output_run_stats {
    my $run = $_[0];

    open OUT, ">", "$OUTPUT_RESULTS_DIR/$run" . "bb-stats.txt";

    print "Results for run $run\n";
    print OUT "Results for run $run\n";

    print "  Coverage: " . $feedback_stats->{$run}->{coverage} . "\n";
    print OUT "  Coverage: " . $feedback_stats->{$run}->{coverage} . "\n";

    close OUT;
    print "done\n\n";
}

sub process_stats_for_input_image {
    my $file = $_[0];
    my $run = $_[1];

    my $basic_blocks_hit = $feedback_stats->{$run}->{basic_blocks_hit};

    open BB, "resources/readpng-bbprinter < $file 2> /dev/null | grep \"__#BB#__\" | grep -v readpng |";
    while (my $line = <BB>) {
        chomp $line;
        $line =~ s/__#BB#__: //;
        $basic_blocks_hit->{$line} = 1;
    }
    close BB;
}
