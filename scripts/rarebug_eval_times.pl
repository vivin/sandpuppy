#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';

my $stats = {};
foreach my $fuzzer("sandpuppy", "afl-plain", "aflplusplus-plain", "aflplusplus-lafintel", "aflplusplus-redqueen") {
    print "Finding solution times for fuzzer $fuzzer...\n";

    $stats->{$fuzzer} = [];
    foreach my $run(1..5) {
        print "  Run $run: ";
        my $command = "scripts/rarebug-findsol smartdsf dirun-$run | grep \"minutes:\" | sed -e 's,^.*: ,,'";
        if ($fuzzer =~ /^afl/) {
            $command = "scripts/rarebug-evals-findsol $fuzzer smartdsf dirun-$run | grep \"minutes:\" | sed -e 's,^.*: ,,'";
        }

        chomp(my $minutes = `$command`);
        $minutes = sprintf("%.2f", $minutes);
        print "$minutes\n";

        push @{$stats->{$fuzzer}}, $minutes;
    }

    print "  Stats: [" . (join ", ", @{$stats->{$fuzzer}}) . "]\n\n";
}
