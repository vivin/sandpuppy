use strict;
use warnings FATAL => 'all';

my $versions = ["1.5.9", "1.6.15"];
my $waypoints = ["plain", "heap", "heap2", "heap3"];
my $input_types = ["queue", "hangs", "crashes"];

sub squash_trace {
    (my $trace) = @_;

    print "incoming: $trace\n";

    my $squashed = "";

    my $seen = {};
    my $root = {};

    my $in_loop = 0;
    my $loop_ctxt = {};
    my $prev = $root;
    foreach my $letter(split //, $trace) {
        my $node;

        if ($in_loop == 0) {

            $node = $seen->{$letter};
            if (!(defined $node)) {
                $node = {
                    value => $letter,
                    prev  => $prev,
                    count => 0
                };

                $prev->{next} = $node;
                $prev = $node;
                $seen->{$letter} = $node;
            } elsif ($node->{count} > 0) {
                print "we are in a loop starting at $node->{value}\n";
                $in_loop = 1;
                $loop_ctxt = {
                    start => $node,
                    end   => $prev,
                    count => ($node != $prev) ? 1 : 2 # if it's a single letter we need to start the count at 2
                };

            } else {
                $prev->{next} = $node;
                $prev = $node;
            }
        } else {
            $node = $seen->{$letter};
            if (defined $node) {
                if ($node == $loop_ctxt->{end}) {
                    $loop_ctxt->{count}++;
                } elsif ($node != $loop_ctxt->{start} && $node->{prev} != $prev && $loop_ctxt->{count} > 1) {
                    # this is the case where we see a character we have seen before, but it is not in the expected
                    # place in the loop (e.g abcdacd).

                    my $in_print_loop = 0;
                    my $ptr = $root;
                    while ($ptr->{next}) {
                        my $_prev = $ptr;
                        $ptr = $ptr->{next};

                        if ($ptr == $loop_ctxt->{start}) {
                            $in_print_loop = 1;
                            $squashed .= "[";
                            print "x[]\n";
                        }

                        $ptr->{count} -= $loop_ctxt->{count}; # don't care if counts of stuff before loop become < 0

                        $squashed .= $ptr->{value};

                        if ($in_print_loop == 0) {
                            delete $_prev->{next};
                            delete $ptr->{prev};

                            delete $seen->{$ptr->{value}};
                        }

                        if ($ptr == $loop_ctxt->{end}) {
                            $squashed .= "]($loop_ctxt->{count})";
                            $in_print_loop = 0;
                        }
                    }

                    $in_loop = 0;

                    # if $prev was loop end, it means $node is now the first node because we deleted everything up to
                    # loop end. otherwise the $node is just node after $prev
                    if ($prev == $loop_ctxt->{end}) {
                        $root->{next} = $node;
                        $node->{prev} = $root;
                    } else {
                        $prev->{next} = $node;
                        $node->{prev} = $node;
                    }

                    # this node is going to be the start of a new sequence
                    delete $node->{next};
                    $node->{count} = 0;
                }

                $prev = $node;
            } elsif ($loop_ctxt->{count} > 1)  {
                # this is the case where we are in a loop, but encountered a character we haven't seen before. this
                # means that the loop is broken.

                # loop is broken so walk back up and print
                # how to do that? well first we need to figure out what we can discard.
                # if the previous node was loop end, we can delete everything up to and including loop end.
                # if the previous node was not loop end, we can only delete all nodes up to and excluding
                # previous node.

                my $in_loop_middle = ($prev != $loop_ctxt->{end});
                my $in_print_loop = 0; # when we actually have to print the loop
                my $ptr = $root;
                while ($ptr->{next}) {
                    my $_prev = $ptr;
                    $ptr = $ptr->{next};

                    if ($ptr == $loop_ctxt->{start}) {
                        $in_print_loop = 1;
                        $squashed .= "[";
                        print "y[]\n";
                    }

                    $ptr->{count} -= $loop_ctxt->{count};

                    $squashed .= $ptr->{value};

                    if (!$in_print_loop || ($in_print_loop && !$in_loop_middle)) {
                        delete $_prev->{next};
                        delete $ptr->{prev};

                        delete $seen->{$ptr->{value}};
                    }

                    if ($ptr == $loop_ctxt->{end}) {
                        $squashed .= "]($loop_ctxt->{count})";
                        $in_print_loop = 0;
                    }
                }

                $in_loop = 0;
                $node = {
                    value => $letter,
                    count => 0
                };
                $seen->{$letter} = $node;

                if ($in_loop_middle == 1) {
                    $prev->{next} = $node;
                    $node->{prev} = $prev;
                } else {
                    $root->{next} = $node;
                    $node->{prev} = $root;
                }

                $prev = $node;
            } else {
                # this is where the problem is with a string like abc123abd. we have b<-d b->d. so we get abd.
                # a doubly-linked list won't work. we need a way to tell if we're getting here after we thought we
                # were in a potential loop. so loop context count is 1. so we could just print from root onwards to 3,
                # not deleting ab in abc123abd. but the problem is we won't be able to compress something like
                # abc123abdabc123abd. maybe what we need is to keep adding things to the linked list, and a different
                # way to tell if we are in a loop. it has to be based on the path.
                #
                # so maybe we calculate a hash code? like we have abc123 and we get a, which we have seen before, which
                # could be a loop, so we look keep an existing path has for abc123a, but then start a new one starting
                # at a as well, and at the first sign that the path doesn't match, we break out. we need to keep
                # multiple entries in the $seen hash, and every time we see a letter again we calculate the hash
                # starting at each one?? ugh. because like what if we have abc123abdabd123abc? i guess we always work
                # inside out maybe? so the idea is to find the innermost repeating sequence. but you will wont be able
                # to compress something like abc123abdabc123abd. i guess maybe every time we see a letter we have seen
                # before, we start calculating the hash starting from there... no can't do that. like in our current
                # example, do we start another hash at each b?. maybe only if we are not already in a possible loop.
                # anyways, this shit doesn't worrrrkkk!! :( :( so tldr. do this sort of same algo but always calculate
                # path hash and when you see a char you have seen before, start calculating path hash from there as
                # well and then keep going. but you need progressive hashes. like a, ab, abc, abc etc. so that you can
                # calculate and compare at each stage. unless maybe you use two pointers and advance. and compare
                # characters. but even so, the problem is that with a string like abc123abdabc123abd, you first have
                # two ptrs at first and second a, which falls through. but then at the third a, where do you put
                # the pointers? you would need three. and you could make a string that could really make your algo
                # OOM. like a zip bomb. but anyways. this is one possible way.
                $node = {
                    value => $letter,
                    prev  => $prev,
                    count => 0
                };

                $prev->{next} = $node;
                $prev = $node;
                $seen->{$letter} = $node;
            }
        }
cd
        $node->{count}++;
    }

    print "squashed is $squashed\n";
    my $ptr = $root;
    while (defined $ptr->{next}) {
        $ptr = $ptr->{next};

        if ($in_loop && $loop_ctxt->{count} > 1 && $ptr == $loop_ctxt->{start}) {
            $squashed .= "[";
            print "z[]\n";
        }

        $squashed .= $ptr->{value};

        if ($in_loop && $loop_ctxt->{count} > 1 && $ptr == $loop_ctxt->{end}) {
            $squashed .= "]($loop_ctxt->{count})";
        }

        if ($in_loop == 1) {
            $ptr->{count} -= $loop_ctxt->{count};
        } else {
            $ptr->{count}--;
        }

        # if we're done, print any trailing partial loops. we know there are partial loops if we're still in a loop
        # at the end and we've seen the node at the start at the loop one more time than the total number of loops.
        if ($in_loop && !(defined $ptr->{next}) && $loop_ctxt->{start}->{count} > 0) {
            $ptr = $loop_ctxt->{start};

            while(defined $ptr) {
                if ($ptr->{count} > 0) {
                    $squashed .= $ptr->{value};
                }

                $ptr = $ptr->{next};
            }
        }
    }

    print "now squashed is $squashed\n";
    # print any trailing partial loops

    return $squashed;
}

print "we have: " . &squash_trace("abc123abd"); # fails!
#print "we have: " . &squash_trace(&squash_trace("abcabcabd")) . "\n";

exit;
my @strings = (
 #   "abcabc",
 #   "abcabcd",
    "abcabcab",
 #   "abcabcb",
 #   "abcabcabd",
 #   "dabcabcd",
 #   "abcdabcdbcd", # all kinds of fucked up
 #   "aaaaaaaa",
 #   "mmmmmmmmfffffffmmmmmmmmmmff", # this is weird because second run is always <char>[<char>](num)????
 #   "mmmmmmffffffnnnnn", # same as above! i think maybe it's creating a new char??
 #   "mm",
 #   "mmmammmammmammma",
 #   "yxbbbabbbabbbazxbbbabbbabbbazyxbbbabbbabbbazxbbbabbbabbbaz"
);

foreach my $string(@strings) {
    my $_string = $string;
    my $i = 1;
    my $done = 0;
    do {
        my $squashed = &squash_trace($_string);
        print "Pass $i for $string: $squashed\n";

        $done = (length($_string) == length($squashed));
        $_string = $squashed;
        $i++;
    } while ($done == 0);

    print "\n";
}

exit;

foreach my $version (@{$versions}) {
    foreach my $waypoint(@{$waypoints}) {
        foreach my $input_type (@{$input_types}) {
            chomp(my @find = `find results/$version-$waypoint/$input_type -type f -name "*.trace" | sort`);

            print "calculating for $version:$waypoint:$input_type...\n";

            foreach my $file(@find) {
                chomp(my $numCalls = `wc -l $file | sed -e 's,^ *,,' | sed -e 's, .*,,'`);
                print OUT "$version,$waypoint,$numCalls\n";
            }
        }
    }

    close OUT;
}

foreach my $version (@{$versions}) {
    foreach my $waypoint(@{$waypoints}) {
        foreach my $input_type (@{$input_types}) {
        }
    }
}

