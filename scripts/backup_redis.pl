#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';

system "mkdir -p /private-nfs/vivin/redis-backup";
while (1) {
    system "cp -v /redis/* /private-nfs/vivin/redis-backup";
    sleep 300;
}
