#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';

if (scalar @ARGV < 1) {
    die "Syntax: $0 <level-numbers> [resume]\n";
}

my @levels = split /,/, $ARGV[0];
my $resume = "";
if ($ARGV[1] && $ARGV[1] eq "resume") {
    $resume = "resume";
} elsif ($ARGV[1]) {
    die "Syntax: $0 $ARGV[0] resume\n";
}

my $total_pods = 46;
my $vanilla_pods = 1;

foreach my $level(@levels) {
    for my $run(1, 2, 3, 4, 5) {
        system "scripts/exp.pl smartdsf spfuzz smbc as l$level-run-$run $resume";

        print "Waiting on $total_pods pods to be ready...\n";
        sleep 5;

        chomp(my $ready = `pod_names | grep "l$level-run-$run" | xargs -I% kubectl logs % | grep "All set\\|Copying previous" | wc -l`);
        while ($ready < $total_pods) {
            print "Waiting on " . ($total_pods - $ready) . " pods to be ready...\n";
            sleep 5;

            chomp($ready = `pod_names | grep "l$level-run-$run" | xargs -I% kubectl logs % | grep "All set\\|Copying previous" | wc -l`);
        }

        system "scripts/exp.pl smartdsf spvanillafuzz smbc as l$level-vanilla-run-$run $resume";

        print "Waiting on $vanilla_pods pods to be ready...\n";
        sleep 5;

        chomp($ready = `pod_names | grep "l$level-vanilla-run-$run" | xargs -I% kubectl logs % | grep "All set\\|Copying previous" | wc -l`);
        while ($ready < $vanilla_pods) {
            print "Waiting on $vanilla_pods pods to be ready...\n";
            sleep 5;

            chomp($ready = `pod_names | grep "l$level-vanilla-run-$run" | xargs -I% kubectl logs % | grep "All set\\|Copying previous" | wc -l`);
        }
    }
}
