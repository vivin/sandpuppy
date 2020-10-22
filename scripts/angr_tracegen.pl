#!/usr/bin/perl

use warnings FATAL => 'all';
use strict;
use Parallel::ForkManager;

  if (scalar @ARGV 

  my $versions = ["1.5.9", "1.6.15"];
  my $waypoints = ["plain", "heap", "heap2", "heap3"];
  my $input_types = ["queue", "hangs", "crashes"];

  my $inputs = [];

  foreach my $version (@{$versions}) {
    foreach my $waypoint(@{$waypoints}) {
      foreach my $input_type (@{$input_types}) {
        chomp(my @find = `find results/$version-$waypoint/$input_type -type f | grep -v "\\.state" | sort`);

        foreach my $file(@find) {
          push @{$inputs}, {
            "waypoint" => $waypoint,
            "version" => $version,
            "input_type" => $input_type,
            "input_file" => $file
          };
        }
      }
    }
  }

  my $manager = Parallel::ForkManager->new(32);

  $manager->run_on_finish(sub {
    my ($pid, $exit_code, $input) = @_;

    my $version = $input->{version};
    my $waypoint = $input->{waypoint};
    my $input_file = $input->{input_file};

    print "$pid: generated trace for version $version using readpng(trace) against $waypoint fuzzer input: $input_file\n";

    my $trace_directory = "results/traces";
    my $trace_file = "$trace_directory/pid-$pid.trace";
    my $new_trace_file = "$input_file.trace";

    system "cp $trace_file $new_trace_file";
    system("rm $trace_file");
  });

  foreach my $input (@{$inputs}) {
    $manager->start($input) and next;

    my $version = $input->{version};
    my $input_file = $input->{input_file};
    my $readpng = "libpng-$version-trace/contrib/libtests/readpng";

    open(STDOUT, "/dev/null");
    open(STDERR, "/dev/null");
    open(STDIN, $input_file);

    exec($readpng) or die("exec: $!");
    # $manager->finish; is not necessary because exec never returns
  }

  $manager->wait_all_children;

