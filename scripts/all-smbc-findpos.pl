#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';

while (1) {
  foreach my $level(0, 2, 3, 4, 5, 7) {
    foreach my $run(1, 2, 3, 4, 5) {
      system "scripts/smbc-find-max-world-pos smartdsf $level l$level-run-$run";
      system "scripts/smbc-find-max-world-pos smartdsf $level l$level-vanilla-run-$run";
    }
  }

  sleep 600;
}
