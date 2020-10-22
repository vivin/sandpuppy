use strict;
use warnings FATAL => 'all';

  my $versions = ["1.5.9", "1.6.15"];
  my $waypoints = ["plain", "heap", "heap2", "heap3"];
  my $input_types = ["queue", "hangs", "crashes"];

  my $results = {};

  foreach my $version (@{$versions}) {
    if (!$results->{$version}) {
      $results->{$version} = {};
    }

    my $versionResults = $results->{$version};

    open OUT, ">", "trace-length-$version.csv";
    print OUT "version,waypoint,calls\n";

    foreach my $waypoint(@{$waypoints}) {
      if (!$versionResults->{$waypoint}) {
        $versionResults->{$waypoint} = {
            total => 0,
            count => 0
        };
      }

      my $versionWaypointResults = $versionResults->{$waypoint};

      foreach my $input_type (@{$input_types}) {
        if (!$versionWaypointResults->{$input_type}) {
          $versionWaypointResults->{$input_type} = {
              total => 0,
              count => 0
          };
        }

        my $versionWaypointInputTypeResults = $versionWaypointResults->{$input_type};

        chomp(my @find = `find results/$version-$waypoint/$input_type -type f -name "*.trace" | sort`);

        print "calculating for $version:$waypoint:$input_type...\n";

        foreach my $file(@find) {

          chomp(my $numCalls = `wc -l $file | sed -e 's,^ *,,' | sed -e 's, .*,,'`);

          print OUT "$version,$waypoint,$numCalls\n";

          $versionWaypointResults->{total} += $numCalls;
          $versionWaypointResults->{count} += 1;

          $versionWaypointInputTypeResults->{total} += $numCalls;
          $versionWaypointInputTypeResults->{count} += 1;
        }
      }
    }

    close OUT;
  }

  foreach my $version (@{$versions}) {
    my $versionResults = $results->{$version};

    foreach my $waypoint(@{$waypoints}) {
      my $versionWaypointResults = $versionResults->{$waypoint};

      if ($versionWaypointResults->{count} > 0) {
        print "$version $waypoint: count = $versionWaypointResults->{count}; avg = " . ($versionWaypointResults->{total} / $versionWaypointResults->{count}) . "\n";
      } else {
        print "$version $waypoint: count = 0; avg = 0\n";
      }

      foreach my $input_type (@{$input_types}) {
        my $versionWaypointInputTypeResults = $versionWaypointResults->{$input_type};

        if ($versionWaypointInputTypeResults->{count} > 0) {
          print "$version $waypoint $input_type: count = $versionWaypointInputTypeResults->{count}; avg = " . ($versionWaypointInputTypeResults->{total} / $versionWaypointInputTypeResults->{count}) . "\n";
        } else {
          print "$version $waypoint $input_type: count = 0; avg = 0\n";
        }
      }
    }
  }

