#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';
use Statistics::Lite qw(mean stddev);

if (scalar @ARGV < 2) {
    die "$0 <experiment> maze[_klee|_ijon]\n";
}

my $experiment = $ARGV[0];
my $maze = $ARGV[1];

if ($maze ne "maze" && $maze ne "maze_ijon" && $maze ne "maze_klee") {
    die "Unknown maze: $maze\n";
}

my @times = ();
foreach my $run(1..5) {
    system "/home/vivin/Projects/phd/scripts/maze-findsol $experiment $maze vanilla-run-$run | tee /tmp/maze-findsol.out";
    chomp(my $minutes = `grep "minutes:" /tmp/maze-findsol.out | sed -e 's,^.*: ,,'`);
    push @times, $minutes;

    print "\n";
}

my $mean = mean @times;
my $stddev = stddev @times;

print "$maze: $mean +/- $stddev minutes\n";
