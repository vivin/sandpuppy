#!/usr/bin/perl

use strict;

if (scalar @ARGV == 0) {
    die "Syntax: $0 <number-of-test-files>";
}

my $num_test_files = $ARGV[0];

my @files = `find . -type f -name "*.base64"`;
chomp @files;

my $total_files = scalar @files;

for (my $i = 0; $i < $num_test_files; $i ++) {
    print "Generating file " . ($i + 1) . " of $num_test_files\n";

    my $filename = `head /dev/urandom | tr -dc A-Za-z0-9 | head -c13`;

    my %used_files = ();
    my $num_commands = 3 + int(rand(2));
    for (my $j = 0; $j < $num_commands; $j ++) {
        my $file = $files[int(rand($total_files))];
        while ($used_files{$file}) {
            $file = $files[int(rand($total_files))];
        }

        $used_files{$file} = 1;
        system("cat $file >> ../$filename && echo >> ../$filename");

   }
}

