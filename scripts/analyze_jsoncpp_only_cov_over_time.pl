#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';
use File::Basename;
use File::Path qw(make_path);
use File::stat;
use List::Util qw(sum min);
use POSIX qw(floor);
use Cpanel::JSON::XS;
use Data::Dumper;

if (scalar @ARGV < 2) {
    print "$0 <experiment> <run-name>\n";
    exit 1;
}

my $EXPERIMENT = $ARGV[0];
my $RUN_NAME = $ARGV[1];
my $BASE_PATH = "/mnt/vivin-nfs";
if (! -d $BASE_PATH) {
    $BASE_PATH = "/media/2tb/phd-workspace/nfs";
}

my $RUN_DIR = "$BASE_PATH/vivin/$EXPERIMENT/jsoncpp/results/$RUN_NAME";
if (! -d $RUN_DIR) {
    print "Cannot find run directory $RUN_DIR\n";
    exit 1;
}

my $RESULTS_DIR = "$RUN_DIR/aggregated";
make_path $RESULTS_DIR;

my $json = Cpanel::JSON::XS->new->ascii->pretty->allow_nonref;

open BBS, '<', "resources/jsoncpp-basic-blocks.txt";
chomp(my @basic_blocks = <BBS>);
close BBS;

my $total_basic_blocks = scalar @basic_blocks;

my $NUM_HOURS = 48;

my @fuzzers = ("afl-plain", "aflplusplus-plain", "aflplusplus-lafintel", "aflplusplus-redqueen", "sandpuppy");
my $fuzzers_coverage_by_hour = { map { $_ => {} } @ fuzzers };
my $fuzzers_sessions_coverage_by_hour = { map { $_ => {} } @fuzzers };
my $fuzzers_coverage_data = { map { $_ => {} } @fuzzers };
foreach my $fuzzer(@fuzzers) {
    print "Processing jsoncpp coverage results for fuzzer $fuzzer...\n\n";
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

    $fuzzers_sessions_coverage_by_hour->{$fuzzer} = { map { $_ => {} } @sessions };
    my $fuzzer_sessions_coverage_by_hour = $fuzzers_sessions_coverage_by_hour->{$fuzzer};

    $fuzzers_coverage_by_hour->{$fuzzer} = { map { $_ => {} } (0..$NUM_HOURS) };
    my $fuzzer_coverage_by_hour  = $fuzzers_coverage_by_hour->{$fuzzer};

    my $file_hashes = {};

    my $num_sessions = scalar @sessions;
    my $i = 0;
    foreach my $session(@sessions) {
        my $dir = "$fuzzer_dir/$session/queue";
        next if ! -e -d $dir;

        print "[" . (++$i) . "/$num_sessions] Processing inputs in session $session...\n";

        chomp (my $num_files = `ls -f $dir | grep -v "^\\." | grep -v ",sync:" | grep "\\+cov" | wc -l`);
        my $count = 0;
        my $ctime_to_basic_blocks_hit = {};

        open FILES, "ls -f $dir |";
        while (my $file = <FILES>) {
            chomp $file;
            if ($file =~ /id:/ && $file !~ /,sync:/ && $file =~ /\+cov/) {
                chomp(my $hash = `sha512sum $dir/$file | awk '{ print \$1; }'`);
                if (!defined $file_hashes->{$hash}) {
                    $file_hashes->{$hash} = 1;

                    print "Processing input " . (++$count) . " of $num_files                    \r";
                    analyze_jsoncpp_coverage("$dir/$file", $ctime_to_basic_blocks_hit);
                } else {
                    print "Skipping input " . (++$count) . " of $num_files (already processed)\r";
                }
            }
        }
        close FILES;

        $fuzzer_sessions_coverage_by_hour->{$session} = { map { $_ => {} } (0..$NUM_HOURS) };
        my $session_coverage_by_hour = $fuzzer_sessions_coverage_by_hour->{$session};
        my $min_ctime = min(keys %{$ctime_to_basic_blocks_hit});
        foreach my $ctime(sort(keys %{$ctime_to_basic_blocks_hit})) {
            my $hour = 1 + floor(($ctime - $min_ctime) / 3600);
            my $session_coverage_for_hour = $session_coverage_by_hour->{$hour};
            my $fuzzer_coverage_for_hour = $fuzzer_coverage_by_hour->{$hour};

            my $basic_blocks_hit = $ctime_to_basic_blocks_hit->{$ctime};
            foreach my $basic_block(keys %{$basic_blocks_hit}) {
                if (!defined $session_coverage_for_hour->{$basic_block}) {
                    $session_coverage_for_hour->{$basic_block} = 0;
                }

                if (!defined $fuzzer_coverage_for_hour->{$basic_block}) {
                    $fuzzer_coverage_for_hour->{$basic_block} = 0;
                }

                $session_coverage_for_hour->{$basic_block} += $basic_blocks_hit->{$basic_block};
                $fuzzer_coverage_for_hour->{$basic_block} += $basic_blocks_hit->{$basic_block};
            }
        }

        # Fill in holes and calculate cumulative coverage
        for my $hour(1..$NUM_HOURS) {
            if (scalar(keys %{$session_coverage_by_hour->{$hour}}) == 0) {
                $session_coverage_by_hour->{$hour} = $session_coverage_by_hour->{$hour - 1};
            } else {
                my $previous_hour_basic_blocks_hit = $session_coverage_by_hour->{$hour - 1};
                my $basic_blocks_hit = $session_coverage_by_hour->{$hour};
                foreach my $basic_block(keys %{$previous_hour_basic_blocks_hit}) {
                    if (!defined $basic_blocks_hit->{$basic_block}) {
                        $basic_blocks_hit->{$basic_block} = 0;
                    }

                    $basic_blocks_hit->{$basic_block} += $previous_hour_basic_blocks_hit->{$basic_block};
                }
            }

            if (scalar(keys %{$fuzzer_coverage_by_hour->{$hour}}) == 0) {
                $fuzzer_coverage_by_hour->{$hour} = $fuzzer_coverage_by_hour->{$hour - 1};
            } else {
                my $previous_hour_basic_blocks_hit = $fuzzer_coverage_by_hour->{$hour - 1};
                my $basic_blocks_hit = $fuzzer_coverage_by_hour->{$hour};
                foreach my $basic_block(keys %{$previous_hour_basic_blocks_hit}) {
                    if (!defined $basic_blocks_hit->{$basic_block}) {
                        $basic_blocks_hit->{$basic_block} = 0;
                    }

                    $basic_blocks_hit->{$basic_block} += $previous_hour_basic_blocks_hit->{$basic_block};
                }
            }
        }
    }

    my $average_basic_block_counts_by_hour = [ map {
        my $hour = $_;
        sum(map { scalar(keys %{$fuzzer_sessions_coverage_by_hour->{$_}->{$hour}}) } @sessions) / $num_sessions;
    } (0..$NUM_HOURS) ];

    $fuzzers_coverage_data->{$fuzzer} = {
        average_basic_blocks_counts => $average_basic_block_counts_by_hour,
        average_coverage            => [ map { $_ / $total_basic_blocks } @{$average_basic_block_counts_by_hour} ],
        basic_blocks_counts         => [ map { scalar(keys %{$fuzzer_coverage_by_hour->{$_}}) } sort {$a <=> $b} (keys %{$fuzzer_coverage_by_hour}) ],
        coverage                    => [ map { scalar(keys %{$fuzzer_coverage_by_hour->{$_}}) / $total_basic_blocks } sort {$a <=> $b} (keys %{$fuzzer_coverage_by_hour}) ],
    };



    print "\n";
    foreach my $hour(0..48) {
        print "Hour $hour:\n";
        print "  basic_blocks=$fuzzers_coverage_data->{$fuzzer}->{basic_blocks_counts}->[$hour]\n";
        print "  coverage=$fuzzers_coverage_data->{$fuzzer}->{coverage}->[$hour]\n";
        print "  avg_basic_blocks=$average_basic_block_counts_by_hour->[$hour]\n";
        print "  avg_coverage=$fuzzers_coverage_data->{$fuzzer}->{average_coverage}->[$hour]\n";
    }
    print "\n";
}

open JSON, ">", "$RESULTS_DIR/only_cov_coverage_data.json";
print JSON $json->encode($fuzzers_coverage_data);
close JSON;

foreach my $hour(sort {$a <=> $b} (keys %{$fuzzers_coverage_by_hour})) {
    open FILE, ">", "$RESULTS_DIR/hour_bb.txt";
    foreach my $bb(sort(keys(%{$fuzzers_coverage_by_hour->{$hour}}))) {
        print FILE "$bb\n";
    }
    close FILE;
}

sub analyze_jsoncpp_coverage {
    my $file = $_[0];
    my $ctime_to_basic_blocks_hit = $_[1];

    my $ctime = stat($file)->ctime;
    if (!defined $ctime_to_basic_blocks_hit->{$ctime}) {
        $ctime_to_basic_blocks_hit->{$ctime} = {};
    }

    my $basic_blocks_hit = $ctime_to_basic_blocks_hit->{$ctime};
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