#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';
use File::Path qw(make_path);
use File::Basename;
use Storable qw{lock_store lock_retrieve};
use Cpanel::JSON::XS;
use Scalar::Util qw{looks_like_number};
use List::Util qw{reduce sum max};
use Data::Dumper;

my $BOOL_MULTIPLIER = 1;
my $NUMBER_MULTIPLIER = 1.5;
my $STRING_MULTIPLIER = 1.5;
my $ARRAY_MULTIPLIER = 2;
my $OBJECT_MULTIPLIER = 2.5;

my $print_only;
if ($ARGV[0] && $ARGV[0] eq "print") {
   $print_only = 1;
} elsif ($ARGV[0]) {
    die "Usage: $0 [print]\n";
}

my $SCRIPT_NAME = basename $0;
my $BASE_PATH = "/mnt/vivin-nfs";
my $STATE_DIR = "/home/vivin/.script-state/$SCRIPT_NAME/space-eval";
if (! -d $BASE_PATH) {
    $BASE_PATH = "/media/2tb/phd-workspace/nfs";
    $STATE_DIR = "/media/2tb/phd-workspace/script-data/$SCRIPT_NAME/space-eval";
}

make_path $STATE_DIR;

my $RUN_DIR = "$BASE_PATH/vivin/smartdsf/jsoncpp/results/space-eval";
my $RESULTS_DIR = "$RUN_DIR/aggregated";
make_path $RESULTS_DIR;

my @fuzzers = ("afl-plain", "aflplusplus-plain", "aflplusplus-lafintel", "aflplusplus-redqueen", "sandpuppy");

my $fuzzer_stats = {};
my $fuzzer_stats_filename = "$RESULTS_DIR/fuzzer_stats.dat";
if ($print_only && ! -e -f $fuzzer_stats_filename) {
    die "Cannot print because saved stats file $fuzzer_stats_filename does not exist\n";
}

if (-e -f $fuzzer_stats_filename) {
    $fuzzer_stats = lock_retrieve $fuzzer_stats_filename;
} else {
    foreach my $fuzzer(@fuzzers) {
        $fuzzer_stats->{$fuzzer} = {
            deepest_nesting_level => 0,
            complexities          => []
        }
    }
}

if ($print_only) {
    foreach my $fuzzer(keys %{$fuzzer_stats}) {
        output_fuzzer_stats($fuzzer);
    }
}

foreach my $fuzzer(@fuzzers) {
    print "Processing jsoncpp results for fuzzer $fuzzer...\n\n";

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
        push @sessions, map { "$sync_prefix-c$_" } (1..11);

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
                my $state_file = "$STATE_DIR/$session-$file";
                if (-e -f $state_file) {
                    print "Skipping input " . (++$count) . " of $num_files (already processed)\r";
                    next;
                }

                system "/home/vivin/Projects/phd/resources/readjson $dir/$file 2>&1 >/dev/null";
                if ($? != 0) {
                    print "Skipping invalid file " . (++$count) . " of $num_files                   \r";
                } else {
                    open my $fh, "<", "$dir/$file" or die "Cannot open file $dir/$file";
                    my $contents = do {local $/; <$fh>};
                    close $fh;

                    my $data = eval { decode_json $contents };
                    if ($@) {
                        print "Skipping invalid file " . (++$count) . " of $num_files                   \r";
                    } else {
                        print "Processing input " . (++$count) . " of $num_files                   \r";
                        print "\n\n$contents\n\n";
                        analyze_json($data, $fuzzer);
                    }
                }

                system "touch $state_file";
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

    my $deepest_nesting_level_ref = \$fuzzer_stats->{$fuzzer}->{deepest_nesting_level};
    my $complexities = $fuzzer_stats->{$fuzzer}->{complexities};

    open OUT, ">", "$RESULTS_DIR/$fuzzer.txt" if !$print_only;

    print "Results for fuzzer $fuzzer\n\n";
    print OUT "Results for fuzzer $fuzzer\n\n" if !$print_only;

    print "  Deepest nesting level: $$deepest_nesting_level_ref\n\n";
    print OUT "  Deepest nesting level: $$deepest_nesting_level_ref\n\n" if !$print_only;

    open COMPLEXITIES, ">", "$RESULTS_DIR/$fuzzer-complexities.dat" if !$print_only;
    print COMPLEXITIES "[" . (join ", ", @{$complexities}) . "]" if !$print_only;
    close COMPLEXITIES if !$print_only;

    print "\n";
    print OUT "\n" if !$print_only;
}

sub analyze_json {
    my $data = $_[0];
    my $fuzzer = $_[1];

    my $deepest_nesting_level_ref = \$fuzzer_stats->{$fuzzer}->{deepest_nesting_level};
    my $complexities = $fuzzer_stats->{$fuzzer}->{complexities};

    my ($complexity, $nesting_level) = getComplexity($data, 0);
    print "\n======================\nComplexity: $complexity, Nesting level: $nesting_level\n======================\n";
    push @{$complexities}, $complexity;

    if ($nesting_level > $$deepest_nesting_level_ref) {
        $$deepest_nesting_level_ref = $nesting_level;
    }
}

# See: https://stackoverflow.com/questions/63284193/how-can-i-easily-measure-the-complexity-of-a-json-object
sub getComplexity {
    my ($json, $current_depth) = @_;

    # boolean
    if (Cpanel::JSON::XS::is_bool $json) {
        return [$BOOL_MULTIPLIER * 1, $current_depth];
    }

    # number
    if (looks_like_number($json)) {
        return [$NUMBER_MULTIPLIER * ($json == 0 ? 0 : log10(abs($json))), $current_depth];
    }

    # string
    if (ref \$json eq "SCALAR") {
        return [$STRING_MULTIPLIER * log10(length($json)), $current_depth];
    }

    # array
    if (ref $json eq "ARRAY") {
        if (scalar @{$json} == 0) {
            return [$ARRAY_MULTIPLIER * 1, $current_depth + 1];
        }

        my @complexity_results = map { getComplexity($_, $current_depth + 1) } @{$json};
        return [
            $ARRAY_MULTIPLIER * (1 + ((sum map { $_->[0] } @complexity_results) / scalar @{$json})),
            max map { $_->[1] } @complexity_results
        ];
    }

    #object
    if (ref $json eq "HASH") {
        my @keys = keys %{$json};
        if (scalar @keys == 0) {
            return [$OBJECT_MULTIPLIER * 1, $current_depth + 1];
        }

        my $avg_keys_complexity = (sum map { getComplexity($_, $current_depth + 1)->[0] } @keys) / scalar @keys;
        my @values_complexity_results = map { getComplexity($_, $current_depth + 1) } values %{$json};
        return [
            $OBJECT_MULTIPLIER * (1 + $avg_keys_complexity + ((sum map { $_->[0] } @values_complexity_results) / scalar @keys)),
            max map {$_->[1] } @values_complexity_results
        ];
    }

    die "Unrecognized type for json: $json";
}

sub log10 {
    return log($_[0])/log(10);
}