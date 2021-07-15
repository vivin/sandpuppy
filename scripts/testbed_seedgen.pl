#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';

my $MAX_VARS = 5;
my $COUNTER_MIN = 5;
my $COUNTER_MAX = 20;
my $MAX_ENUM_VALUE = 7;
my $MIN_NUM_ENUM_VALUES = 50;
my $MAX_NUM_ENUM_VALUES = 128;

if (scalar @ARGV == 0) {
    print "Usage: $0 <num-inputs-per-var-num>\n";
    exit(1);
}

my @seed_file_names = (
    "first",
    "second",
    "third",
    "fourth",
    "fifth"
);

srand(time);

sub get_random_enum_values() {
    my $num_values = int(rand($MAX_NUM_ENUM_VALUES - $MIN_NUM_ENUM_VALUES)) + $MIN_NUM_ENUM_VALUES;
    return join ",", map { int(rand($MAX_ENUM_VALUE + 1)) } (0 .. $num_values);
}

sub get_random_limit() {
    return int(rand($COUNTER_MAX - $COUNTER_MIN) + $COUNTER_MIN);
}

my $num_inputs_per_var_num = $ARGV[0];
for my $input_num (0 .. $num_inputs_per_var_num - 1) {
   foreach my $enum_mod_type ("s", "m") {
       for (my $var_num = 1; $var_num <= $MAX_VARS; $var_num++) {
           my $filename = "$seed_file_names[$var_num - 1]-$input_num.$enum_mod_type.txt";
           my $input = "$var_num:$var_num:" . # static pos and neg
                       "$var_num;${\(get_random_limit())}:$var_num;${\(get_random_limit())}:" . # dynamic pos and neg
                       "$var_num:$var_num:" . # static varying pos and neg
                       "$var_num;${\(get_random_limit())}:$var_num;${\(get_random_limit())}:" . # dynamic varying pos and neg
                       "$var_num;$enum_mod_type;${\(get_random_enum_values())}";

           print "Writing resources/seeds/vctestbed/tracegen/$filename\n";
           open my $OUT, ">", "resources/seeds/vctestbed/tracegen/$filename";
           print $OUT $input;
           close $OUT
       }
   }
}