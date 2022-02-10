#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';

foreach my $fuzzer("afl-plain", "aflplusplus-plain", "aflplusplus-lafintel", "aflplusplus-redqueen") {
    my $sync_prefix = $fuzzer;
    if ($fuzzer eq "aflplusplus-lafintel") {
        $sync_prefix = "aflplusplus-lafi";
    } elsif ($fuzzer eq "aflplusplus-redqueen") {
        $sync_prefix = "aflplusplus-redq";
    }

    system "kuboid/scripts/pod_create -n \"smartdsf-libtpms-di-ec-run--$fuzzer-main\" -i vivin/sandpuppy /private-nfs/vivin/smartdsf/libtpms/diverse-seeds-$fuzzer di-ec-run $sync_prefix-main\n";
    foreach my $child(1..48) {
        system "kuboid/scripts/pod_create -n \"smartdsf-libtpms-di-ec-run--$fuzzer-child-$child\" -i vivin/sandpuppy /private-nfs/vivin/smartdsf/libtpms/diverse-seeds-$fuzzer di-ec-run $sync_prefix-c$child\n";
    }
}


