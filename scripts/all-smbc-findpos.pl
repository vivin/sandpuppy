#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';

my $BASE_PATH = "/mnt/vivin-nfs";
if (! -d $BASE_PATH) {
  $BASE_PATH = "/media/2tb/phd-workspace/nfs";
}

my $output_file = "$BASE_PATH/vivin/smartdsf/smbc/results/max_world_pos.txt";
while (1) {
  foreach my $level(0, 2, 3, 4, 5, 7) {
    foreach my $run(1, 2, 3, 4, 5) {
      system "scripts/smbc-find-max-world-pos smartdsf $level l$level-run-$run >> $output_file.tmp 2>&1";
      system "scripts/smbc-find-max-world-pos smartdsf $level l$level-vanilla-run-$run >> $output_file.tmp 2>&1";
    }
  }

  system "mv $output_file.tmp $output_file";
  sleep 600;
}
