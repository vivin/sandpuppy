use strict;
use warnings FATAL => 'all';

my $versions = ["1.5.9", "1.6.15"];
my $waypoints = ["plain", "heap", "heap2", "heap3"];
my $input_types = ["queue", "hangs", "crashes"];

sub dump_trie {
    no warnings 'recursion';
    (my $fh, my $node, my $prefix, my $show_counts, my $terse) = @_;

    my $short_op = $node->{op};
    $short_op =~ s/^([a-z])[a-z]+\./$1/;
    if (!$node->{has_children}) {
        my $line = !$terse ? "$prefix->$node->{op}" : "$prefix" . $short_op; #substr($node->{op}, 0, 1);
        if ($show_counts == 1) {
            $line = "$line($node->{count})"
        }

        print $fh "$line\n";
        return;
    }

    $prefix = !$terse ? ("$prefix->" . "$node->{op}") : "$prefix" . $short_op; #substr($node->{op}, 0, 1);
    if ($show_counts == 1) {
        $prefix = "$prefix($node->{count})";
    }

    if ($node->{end}) {
        print $fh "$prefix\n"; # put * at the end of prefix if you want to tag this as a path that is a common ancestor
    }

    foreach my $op(keys %{$node}) {
        if (ref $node->{$op} eq ref {}) {
            &dump_trie($fh, $node->{$op}, $prefix, $show_counts, $terse);
        }
    }
}

foreach my $version (@{$versions}) {
    foreach my $waypoint(@{$waypoints}) {

        my $trie = {};

        foreach my $input_type (@{$input_types}) {
            chomp(my @find = `find results/$version-$waypoint/$input_type -type f -name "*.trace" | sort`);

            print "processing $version:$waypoint:$input_type...\n";

            foreach my $file(@find) {
                my $node = $trie;
                chomp(my $numCalls = `wc -l $file | sed -e 's,^ *,,' | sed -e 's, .*,,'`);

                my $i = 0;
                open IN, "<", $file;
                while (<IN>) {
                    chomp;
                    my $op = $_;
                    #$op =~ s/\..*$//;
                    $op =~ s/\(.*$//;

                    if (!$node->{$op}) {
                        if ($node != $trie) {
                            $node->{has_children} = 1;
                        }

                        $node->{$op} = {
                            op => $op,
                            count => 0,
                            end   => 0
                        };
                    }

                    $node = $node->{$op};
                    $node->{count}++;

                    if ($i == $numCalls - 1) {
                        $node->{end} = 1;
                    }

                    $i++;
                }

                close IN;
            }
        }

        #open my $fh1, ">", "trace-$version-$waypoint.dump";
        open my $fh2, ">", "trace-$version-$waypoint-no-counts-bb.dump";
        foreach my $op(keys %{$trie}) {
            #&dump_trie($fh1, $trie->{$op}, "root", 1, 0);
            &dump_trie($fh2, $trie->{$op}, "r", 0, 1);
        }
        close $fh2;
        #close $fh1;
    }


    #close OUT;
}

