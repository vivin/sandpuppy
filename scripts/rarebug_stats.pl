#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';
use Statistics::Lite qw(mean stddev);

if (scalar @ARGV < 1) {
    die "$0 <experiment>\n";
}

my $experiment = $ARGV[0];

my @times = ();
foreach my $run(1..5) {
    system "/home/vivin/Projects/phd/scripts/rarebug-findsol $experiment run-$run | tee /tmp/rarebug-findsol.out";
    chomp(my $minutes = `grep "minutes:" /tmp/rarebug-findsol.out | sed -e 's,^.*: ,,'`);
    push @times, $minutes;

    print "\n";
}

my $mean = mean @times;
my $stddev = stddev @times;

print "rarebug: $mean +/- $stddev minutes\n";