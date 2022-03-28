#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';

foreach my $fuzzer("afl-plain") {#}, "aflplusplus-plain", "aflplusplus-lafintel", "aflplusplus-redqueen") {
    foreach my $run(1..1) {
        my $sync_prefix = $fuzzer;
        if ($fuzzer eq "aflplusplus-lafintel") {
            $sync_prefix = "aflplusplus-lafi";
        } elsif ($fuzzer eq "aflplusplus-redqueen") {
            $sync_prefix = "aflplusplus-redq";
        }

        system "kuboid/scripts/pod_create -n \"smartdsf-rarebug-trun-$run--$fuzzer-main\" -i vivin/sandpuppy /private-nfs/vivin/smartdsf/rarebug/diverse-seeds-$fuzzer trun-$run $sync_prefix-main\n";
        foreach my $child(1..1) {
            system "kuboid/scripts/pod_create -n \"smartdsf-rarebug-trun-$run--$fuzzer-c$child\" -i vivin/sandpuppy /private-nfs/vivin/smartdsf/rarebug/diverse-seeds-$fuzzer trun-$run $sync_prefix-c$child\n";
        }
    }
}


