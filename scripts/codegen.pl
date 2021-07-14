use strict;
use warnings FATAL => 'all';

my $NUM_VARS = 5;

for(my $i = 1; $i <= $NUM_VARS; $i++) {
    my $limit = $i * 10;
    print <<"HERE";
void fn_static_pos_counter_$i() {
  for (int static_pos_counter_$i = 1; static_pos_counter_$i <= $limit; static_pos_counter_$i ++) {
    printf("static_pos_counter_$i: %d\\n", static_pos_counter_$i);
  }
}

HERE
}

for(my $i = 1; $i <= $NUM_VARS; $i++) {
    my $limit = $i * 10;
    print <<"HERE";
void fn_static_neg_counter_$i() {
  for (int static_neg_counter_$i = $limit; static_neg_counter_$i >= 1; static_neg_counter_$i --) {
    printf("static_neg_counter_$i: %d\\n", static_neg_counter_$i);
  }
}

HERE
}

for(my $i = 1; $i <= $NUM_VARS; $i++) {
    print <<"HERE";
void fn_dynamic_pos_counter_$i(int limit) {
  if (limit < 0 || limit >= 100) {
    exit(1);
  }

  for (int dynamic_pos_counter_$i = 1; dynamic_pos_counter_$i <= limit; dynamic_pos_counter_$i ++) {
    printf("dynamic_pos_counter_$i: %d\\n", dynamic_pos_counter_$i);
  }
}

HERE
}

for(my $i = 1; $i <= $NUM_VARS; $i++) {
    print <<"HERE";
void fn_dynamic_neg_counter_$i(int limit) {
  if (limit < 0 || limit >= 100) {
    exit(1);
  }

  for (int dynamic_neg_counter_$i = limit; dynamic_neg_counter_$i >= 1; dynamic_neg_counter_$i --) {
    printf("dynamic_neg_counter_$i: %d\\n", dynamic_neg_counter_$i);
  }
}

HERE
}

for(my $i = 1; $i <= $NUM_VARS; $i++) {
    my $limit = $i * 25;
    print <<"HERE";
void fn_varying_static_pos_counter_$i() {
  int step = 0;
  for (int varying_static_pos_counter_$i = 1; varying_static_pos_counter_$i <= $limit; varying_static_pos_counter_$i += step) {
    printf("varying_static_pos_counter_$i: %d\\n", varying_static_pos_counter_$i);
    step++;
  }
}

HERE
}

for(my $i = 1; $i <= $NUM_VARS; $i++) {
    my $limit = $i * 25;
    print <<"HERE";
void fn_varying_static_neg_counter_$i() {
  int step = 0;
  for (int varying_static_neg_counter_$i = $limit; varying_static_neg_counter_$i >= 1; varying_static_neg_counter_$i -= step) {
    printf("varying_static_neg_counter_$i: %d\\n", varying_static_neg_counter_$i);
    step++;
  }
}

HERE
}

for(my $i = 1; $i <= $NUM_VARS; $i++) {
    print <<"HERE";
void fn_varying_dynamic_pos_counter_$i(int limit) {
  if (limit < 0 || limit >= 100) {
    exit(1);
  }

  int step = 0;
  for (int varying_dynamic_pos_counter_$i = 1; varying_dynamic_pos_counter_$i <= limit; varying_dynamic_pos_counter_$i += step) {
    printf("varying_dynamic_pos_counter_$i: %d\\n", varying_dynamic_pos_counter_$i);
    step++;
  }
}

HERE
}

for(my $i = 1; $i <= $NUM_VARS; $i++) {
    print <<"HERE";
void fn_varying_dynamic_neg_counter_$i(int limit) {
  if (limit < 0 || limit >= 100) {
    exit(1);
  }

  int step = 0;
  for (int varying_dynamic_neg_counter_$i = limit; varying_dynamic_neg_counter_$i >= 1; varying_dynamic_neg_counter_$i -= step) {
    printf("varying_dynamic_neg_counter_$i: %d\\n", varying_dynamic_neg_counter_$i);
    step++;
  }
}

HERE
}

for(my $i = 1; $i <= $NUM_VARS; $i++) {
    my $limit = 5;
    print <<"HERE";
void fn_enum_var_single_mod_$i(int value) {
  if (value < 0 || value >= $limit) {
    exit(1);
  }

  int enum_var_single_mod_$i = value;
  printf("enum_var_single_mod_$i: %d\\n", enum_var_single_mod_$i);
}

HERE
}

for(my $i = 1; $i <= $NUM_VARS; $i++) {
    my $limit = 5;
    print <<"HERE";
void fn_enum_var_multi_mod_$i(int value) {
  if (value < 0 || value >= $limit) {
    exit(1);
  }

  int enum_var_multi_mod_$i;
  if (value == 0) {
    enum_var_multi_mod_$i = value + 0;
HERE
    print "  }";
    for (my $j = 1; $j < $limit; $j++) {
        print " else if (value == $j) {\n    enum_var_multi_mod_$i = value + $j;\n  }";
    }

    print "\n\n  printf(\"enum_var_multi_mod_$i: %d\\n\", enum_var_multi_mod_$i);\n}\n\n";
}
