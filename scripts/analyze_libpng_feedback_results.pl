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
my $feedback_stats_filename = "$OUTPUT_RESULTS_DIR/feedback_stats.dat";
if ($print_only && ! -e -f $feedback_stats_filename) {
    die "Cannot print because saved stats file $feedback_stats_filename does not exist\n";
}

if (-e -f $feedback_stats_filename) {
    $feedback_stats = lock_retrieve $feedback_stats_filename;
} else {
    foreach my $run(@runs) {
        $feedback_stats->{$run} = {
            number_of_chunks_over_time        => {},
            number_of_unique_chunks_over_time => {},
            image_height_over_time            => {},
            image_width_over_time             => {}
        };

        foreach my $hour(0..12) {
            $feedback_stats->{$run}->{number_of_chunks_over_time}->{$hour} = [];
            $feedback_stats->{$run}->{number_of_unique_chunks_over_time}->{$hour} = [];
            $feedback_stats->{$run}->{image_height_over_time}->{$hour} = [];
            $feedback_stats->{$run}->{image_width_over_time}->{$hour} = [];
        }
    }
}

if ($print_only) {
    foreach my $run(keys %{$feedback_stats}) {
        output_run_stats($run);
    }
}

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

        chomp(my $first_input = `find $dir -maxdepth 1 -mindepth 1 -name "id:000000,*"`);
        chomp(my $start_time = `stat -c '%Y' "$first_input"`);

        print "[" . (++$i) . "/$num_sessions] Processing inputs in session $session...\n";

        chomp (my $num_files = `ls -f $dir | grep -v "^\\." | grep -v ",sync:" | wc -l`);
        my $count = 0;
        open FILES, "ls -f $dir |";
        while (my $file = <FILES>) {
            chomp $file;

            if ($file =~ /id:/ && $file !~ /,sync:/) {
                print "Processing input " . (++$count) . " of $num_files                   \r";
                process_stats_for_input_image("$dir/$file", $run, $start_time);
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

    my $number_of_chunks_over_time = $feedback_stats->{$run}->{number_of_chunks_over_time};
    my $number_of_unique_chunks_over_time = $feedback_stats->{$run}->{number_of_unique_chunks_over_time};
    my $image_height_over_time = $feedback_stats->{$run}->{image_height_over_time};
    my $image_width_over_time = $feedback_stats->{$run}->{image_width_over_time};

    my @average_number_of_chunks_over_time = map {
        scalar @{$number_of_chunks_over_time->{$_}} > 0 ? mean @{$number_of_chunks_over_time->{$_}} : 0
    } (0..12);
    my @average_number_of_unique_chunks_over_time = map {
        scalar @{$number_of_unique_chunks_over_time->{$_}} > 0 ? mean @{$number_of_unique_chunks_over_time->{$_}} : 0
    } (0..12);
    my @average_image_height_over_time = map {
        scalar @{$image_height_over_time->{$_}} > 0 ? mean @{$image_height_over_time->{$_}} : 0
    } (0..12);
    my @average_image_width_over_time = map {
        scalar @{$image_width_over_time->{$_}} > 0 ? mean @{$image_width_over_time->{$_}} : 0
    } (0..12);

    open OUT, ">", "$OUTPUT_RESULTS_DIR/$run" . "-stats.txt";

    print "Results for run $run\n\n";
    print OUT "Results for fuzzer $run\n\n";

    print "  Average number of chunks over time: [" . (join ", ", @average_number_of_chunks_over_time) . "]\n";
    print OUT "  Average number of chunks over time: [" . (join ", ", @average_number_of_chunks_over_time) . "]\n";

    print "  Average number of unique chunks over time: [" . (join ", ", @average_number_of_unique_chunks_over_time) . "]\n";
    print OUT "  Average number of unique chunks over time: [" . (join ", ", @average_number_of_unique_chunks_over_time) . "]\n";

    print "  Average image height over time: [" . (join ", ", @average_image_height_over_time) . "]\n";
    print OUT "  Average image height over time: [" . (join ", ", @average_image_height_over_time) . "]\n";

    print "  Average image width over time: [" . (join ", ", @average_image_width_over_time) . "]\n";
    print OUT "  Average image width over time: [" . (join ", ", @average_image_width_over_time) . "]\n";

    close OUT;
    print "done\n\n";
}

sub process_stats_for_input_image {
    my $file = $_[0];
    my $run = $_[1];
    my $start_time = $_[2];

    chomp(my $input_found_time = `stat -c '%Y' "$file"`);
    my $hour = floor (($input_found_time - $start_time) / (60 * 60));
    my $number_of_chunks_over_time_for_hour = $feedback_stats->{$run}->{number_of_chunks_over_time}->{$hour};
    my $number_of_unique_chunks_over_time_for_hour = $feedback_stats->{$run}->{number_of_unique_chunks_over_time}->{$hour};
    my $image_height_over_time_for_hour = $feedback_stats->{$run}->{image_height_over_time}->{$hour};
    my $image_width_over_time_for_hour = $feedback_stats->{$run}->{image_width_over_time}->{$hour};

    my $num_chunks = 0;
    my $chunks = {};
    my $height = 0;
    my $width = 0;
    open PNGSTATS, "pngcheck -fv $file |";
    while (my $line = <PNGSTATS>) {
        chomp $line;
        if ($line =~ /^\s+chunk [A-Z]/) {
            $num_chunks++;

            my $chunk = $line;
            $chunk =~ s/^\s+ chunk //;
            $chunk =~ s/\s.*$//;

            $chunks->{$chunk} = 1;
        } elsif ($line =~ /^\s+\d+ x \d+ image/) {
            my $dimensions = $line;
            $dimensions =~ s/^\s+//;
            $dimensions =~ s/ image.*$//;

            ($height, $width) = split / x /, $dimensions;
        }
    }
    close PNGSTATS;

    push @{$number_of_chunks_over_time_for_hour}, $num_chunks;
    push @{$number_of_unique_chunks_over_time_for_hour}, scalar keys %{$chunks};
    push @{$image_height_over_time_for_hour}, $height;
    push @{$image_width_over_time_for_hour}, $width;
}
