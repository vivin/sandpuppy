#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';
use File::Path qw(make_path);
use File::stat;
use File::Basename;
use List::Util qw(sum min);
use POSIX qw(floor);
use YAML::XS;
use Cpanel::JSON::XS;

my $BASE_PATH = glob "~/Projects/phd";
my $RESOURCES = "$BASE_PATH/resources";

my $SCRIPT_NAME = basename $0;

if (scalar @ARGV < 4) {
    die "Syntax: $SCRIPT_NAME <experiment> <subject>[:version] <run-name> <num-children>\n";
}

my $experiment = $ARGV[0];
my $full_subject = $ARGV[1];
my $run_name = $ARGV[2];
my $num_children = $ARGV[3];
my $original_subject = $full_subject;
my $subject = $full_subject;
my $version;
if ($full_subject =~ /:/) {
    ($subject, $version) = split(/:/, $full_subject);
    $full_subject =~ s/:/-/;
}

my $RESULTS_BASE_PATH = "/mnt/vivin-nfs";
if (! -d $RESULTS_BASE_PATH) {
    $RESULTS_BASE_PATH = "/media/2tb/phd-workspace/nfs";
}

my $RUN_DIR = "$RESULTS_BASE_PATH/vivin/$experiment/$full_subject/results/$run_name";
if (! -d $RUN_DIR) {
    print "Cannot find run directory $RUN_DIR\n";
    exit 1;
}

my $fuzz_config = YAML::XS::LoadFile("$BASE_PATH/resources/fuzz_config.yml");

my $RESULTS_DIR = "$RUN_DIR/aggregated";
make_path $RESULTS_DIR;

my $json = Cpanel::JSON::XS->new->ascii->pretty->allow_nonref;

my @fuzzers = ("afl-plain", "aflplusplus-plain", "aflplusplus-lafintel", "aflplusplus-redqueen");
my $fuzzers_coverage = { map { $_ => {} } @ fuzzers };
my $fuzzers_coverage_by_hour = { map { $_ => {} } @ fuzzers };
foreach my $fuzzer(@fuzzers) {
    my $basic_blocks_hit = {};
    my $ctime_to_basic_blocks_hit = {};

    print "Processing $full_subject results for fuzzer $fuzzer...\n\n";

    my $fuzzer_dir = "$RUN_DIR/$fuzzer-sync";
    next if ! -e -d $fuzzer_dir;

    my $sync_prefix = $fuzzer;
    if ($fuzzer eq "aflplusplus-lafintel") {
        $sync_prefix = "aflplusplus-lafi";
    } elsif ($fuzzer eq "aflplusplus-redqueen") {
        $sync_prefix = "aflplusplus-redq";
    }

    my @sessions = ("$sync_prefix-main");
    push @sessions, map { "$sync_prefix-c$_" } (1..$num_children);

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

            if ($file =~ /id:/ && $file =~ /\+cov/ && $file !~ /,sync:/) {
                print "Processing input " . (++$count) . " of $num_files                   \r";
                get_coverage("$dir/$file", $basic_blocks_hit, $ctime_to_basic_blocks_hit);
            } else {
                print "Skipping input " . (++$count) . " of $num_files                     \r";
            }
        }
        close FILES;
    }

    $fuzzers_coverage->{$fuzzer} = scalar keys(%{$basic_blocks_hit});

    open BBS_HIT, ">", "$RESULTS_DIR/$fuzzer-basic-blocks-hit.txt";
    foreach my $bb(sort(keys(%{$basic_blocks_hit}))) {
        print BBS_HIT "$bb\n";
    }
    close BBS_HIT;

    $fuzzers_coverage_by_hour->{$fuzzer}->{$_} = {} for (1..24);

    my $min_ctime = min(keys %{$ctime_to_basic_blocks_hit});
    foreach my $ctime(sort(keys %{$ctime_to_basic_blocks_hit})) {
        my $hour = 1 + floor(($ctime - $min_ctime) / 3600);
        if ($hour > 24) {
            $hour = 24;
        }

        my $fuzzer_coverage_for_hour = $fuzzers_coverage_by_hour->{$fuzzer}->{$hour};
        my $ctime_basic_blocks_hit = $ctime_to_basic_blocks_hit->{$ctime};
        foreach my $basic_block(keys %{$ctime_basic_blocks_hit}) {
            $fuzzer_coverage_for_hour->{$basic_block} = 1;
        }
    }

    # Fill up holes in the coverage data at the top
    if (scalar keys %{$fuzzers_coverage_by_hour->{$fuzzer}->{1}} == 0) {
        my $first_hour_with_data = 0;
        foreach my $hour(2..24) {
            if (scalar keys %{$fuzzers_coverage_by_hour->{$fuzzer}->{$hour}} > 0) {
                $first_hour_with_data = $hour;
                last;
            }
        }

        foreach my $hour(1..$first_hour_with_data - 1) {
            $fuzzers_coverage_by_hour->{$fuzzer}->{$hour} = $fuzzers_coverage_by_hour->{$fuzzer}->{$first_hour_with_data};
        }
    }

    # Merge coverage down from hour 1 to hour 24
    foreach my $hour(2..24) {
        foreach my $basic_block(keys %{$fuzzers_coverage_by_hour->{$fuzzer}->{$hour - 1}}) {
            $fuzzers_coverage_by_hour->{$fuzzer}->{$hour}->{$basic_block} = 1;
        }
    }

    # Replace the basic-blocks hash with the count of the keys
    foreach my $hour(1..24) {
        $fuzzers_coverage_by_hour->{$fuzzer}->{$hour} = scalar keys(%{$fuzzers_coverage_by_hour->{$fuzzer}->{$hour}});
    }
}

open JSON, ">", "$RESULTS_DIR/fuzzers-coverage.json";
print JSON $json->encode($fuzzers_coverage);
close JSON;

open JSON, ">", "$RESULTS_DIR/fuzzers-coverage-over-time.json";
print JSON $json->encode($fuzzers_coverage_by_hour);
close JSON;

sub get_coverage {
    my $file = $_[0];
    my $basic_blocks_hit = $_[1];
    my $ctime_to_basic_blocks_hit = $_[2];

    my $ctime = stat($file)->ctime;
    if (!defined $ctime_to_basic_blocks_hit->{$ctime}) {
        $ctime_to_basic_blocks_hit->{$ctime} = {};
    }

    my $ctime_basic_blocks_hit = $ctime_to_basic_blocks_hit->{$ctime};

    my $binary = "$RESOURCES/binaries/$fuzz_config->{$subject}->{binary_name}-bbprinter";
    my $command = "$binary $fuzz_config->{$subject}->{argument}";
    $command =~ s/\@\@/$file/;

    chomp(my @data = `$command 2> /dev/null | grep \"__#BB#__\" | grep -v $binary | sed 's,__#BB#__: ,,'`);
    foreach my $bb(@data) {
        $basic_blocks_hit->{$bb} = 1;
        $ctime_basic_blocks_hit->{$bb} = 1;
    }
}
#:81,104!sed -e 's,",,' | sort -n | sed -e 's,[0-9],"&,'