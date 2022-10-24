#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';

use Cpanel::JSON::XS;
use Scalar::Util qw{looks_like_number};
use List::Util qw{reduce sum max};
use Data::Dumper;

my $BOOL_MULTIPLIER = 1;
my $NUMBER_MULTIPLIER = 1.5;
my $STRING_MULTIPLIER = 1.5;
my $ARRAY_MULTIPLIER = 2;
my $OBJECT_MULTIPLIER = 2.5;

my $file = $ARGV[0];
open my $fh, "<", $file or die "Cannot open file $file";
my $data = decode_json do {local $/; <$fh>};
close $fh;

my $results = getComplexity($data, 0);
print "Complexity: $results->[0] Max Depth: $results->[1]\n";

sub getComplexity {
    my ($json, $current_depth) = @_;

    # boolean
    if (Cpanel::JSON::XS::is_bool $json) {
        return [$BOOL_MULTIPLIER * 1, $current_depth];
    }

    # number
    if (looks_like_number($json)) {
        return [$NUMBER_MULTIPLIER * ($json == 0 ? 0 : log10(abs($json))), $current_depth];
    }

    # string
    if (ref \$json eq "SCALAR") {
        return [$STRING_MULTIPLIER * log10(length($json)), $current_depth];
    }

    # array
    if (ref $json eq "ARRAY") {
        if (scalar @{$json} == 0) {
            return [$ARRAY_MULTIPLIER * 1, $current_depth + 1];
        }

        my @complexity_results = map { getComplexity($_, $current_depth + 1) } @{$json};
        return [
            $ARRAY_MULTIPLIER * (1 + ((sum map { $_->[0] } @complexity_results) / scalar @{$json})),
            max map { $_->[1] } @complexity_results
        ];
    }

    #object
    if (ref $json eq "HASH") {
        my @keys = keys %{$json};
        if (scalar @keys == 0) {
            return [$OBJECT_MULTIPLIER * 1, $current_depth + 1];
        }

        my $avg_keys_complexity = (sum map { getComplexity($_, $current_depth + 1)->[0] } @keys) / scalar @keys;
        my @values_complexity_results = map { getComplexity($_, $current_depth + 1) } values %{$json};
        return [
            $OBJECT_MULTIPLIER * (1 + $avg_keys_complexity + ((sum map { $_->[0] } @values_complexity_results) / scalar @keys)),
            max map {$_->[1] } @values_complexity_results
        ];
    }

    die "Unrecognized type for json: $json";
}

sub log10 {
    return log($_[0])/log(10);
}