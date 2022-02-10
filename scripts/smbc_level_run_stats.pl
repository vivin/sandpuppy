#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';
use Statistics::Lite qw(mean median stddev);

my %levels_with_solutions = (
#    4 => {
#        sandpuppy => 0,
#        vanilla   => 0
#    },
#    7 => {
#        sandpuppy => 0,
#        vanilla   => 0
#    }
);

my %level_to_world = (
    0  => "1-1",
    2  => "1-2",
    3  => "1-3",
    4  => "1-4", # solution is when position >= 2236
    5  => "2-1",
    7  => "2-2", # solution is when position >= 3013
    8  => "2-3", # solution is when position >= 3574
    9  => "2-4", # solution is when position >= 2251
    10 => "3-1",
    11 => "3-2",
    12 => "3-3",
    13 => "3-4",
    14 => "4-1",
    16 => "4-2",
    17 => "4-3",
    18 => "4-4",
    19 => "5-1",
    20 => "5-2",
    21 => "5-3",
    22 => "5-4",
    23 => "6-1",
    24 => "6-2",
    25 => "6-3",
    26 => "6-4",
    27 => "7-1",
    29 => "7-2",
    30 => "7-3",
    31 => "7-4",
    32 => "8-1",
    33 => "8-2",
    34 => "8-3",
    35 => "8-4"
);
my $level_to_best_sandpuppy_results = {};
my $level_to_best_vanilla_results = {};

open RESULTS, "grep \"Target:\\|Level:\\|Run:\\|^ from \\|Maximum\\|resources/smbc\" /mnt/vivin-nfs/vivin/smartdsf/smbc/results/max_world_pos.txt  | sed 's,/media.*nfs,/mnt/vivin-nfs,' | sed '/ resources.*/{G;} ' |";
while (my $line = <RESULTS>) {
    next if $line eq "\n";

    chomp(my $target_line = $line);
    chomp(my $level_line = <RESULTS>);
    chomp(my $run_line = <RESULTS>);
    chomp(my $max_world_coordinate_line = <RESULTS>);
    chomp(my $input_line = <RESULTS>);
    chomp(my $command_line = <RESULTS>);

    my $vanilla = 0;

    my $target = $target_line;
    $target =~ s/^.*: //;

    my $level = $level_line;
    $level =~ s/^.*: //;

    my $run = $run_line;
    if ($run =~ /vanilla/) {
        $vanilla = 1;
        $run =~ s/^.*: l\d+-vanilla-run-//;
    } else {
        $run =~ s/^.*: l\d+-run-//;
    }

    my $max_world_coordinate = $max_world_coordinate_line;
    $max_world_coordinate =~ s/^.*: //;

    my $world_pos = $max_world_coordinate;
    $world_pos =~ s/[()]//g;
    $world_pos =~ s/,.*$//;

    my $input = $input_line;
    $input =~ s/from //;

    my $level_to_best_results;
    if ($vanilla != 1) {
        $level_to_best_results = $level_to_best_sandpuppy_results;
    } else {
        $level_to_best_results = $level_to_best_vanilla_results;
    }

    if (!$level_to_best_results->{$level}) {
        $level_to_best_results->{$level} = {
            max_world_pos    => 0,
            target           => "",
            run              => "",
            coordinate       => "",
            input            => "",
            command          => "",
            run_best_results => []
        };
    }

    my $level_result = $level_to_best_results->{$level};
    if ($world_pos > $level_result->{max_world_pos} ||
        ($world_pos == $level_result->{max_world_pos} && parse_to_seconds($input) < parse_to_seconds($level_result->{input}))
    ) {
        $level_result->{max_world_pos} = $world_pos;
        $level_result->{target} = $target;
        $level_result->{run} = $run;
        $level_result->{coordinate} = $max_world_coordinate;
        $level_result->{input} = $input;
        $level_result->{command} = $command_line;
    }

    $level_to_best_results->{$level}->{run_best_results}->[$run] = {
        target     => $target,
        run        => $run,
        coordinate => $max_world_coordinate,
        input      => $input,
        command    => $command_line,
        found_time => parse_to_seconds($input)
    };
}
close RESULTS;

print "Vanilla AFL Results\n\n";
print_results($level_to_best_vanilla_results, "vanilla");

print "=" x 200 . "\n\n";

print "SandPuppy Results\n\n";
print_results($level_to_best_sandpuppy_results, "sandpuppy");

sub print_results {
    my $level_to_best_results = $_[0];
    my $fuzzer = $_[1];

    foreach my $level(sort { $a <=> $b } keys(%{$level_to_best_results})) {
        if (defined $levels_with_solutions{$level} && $levels_with_solutions{$level}->{$fuzzer}) {
            print "\033[32;1m";
        }

        print "  Best results from each run for Level $level (World $level_to_world{$level}):\n";

        my @found_times = ();
        foreach my $run(1, 2, 3, 4, 5) {
            print "    Run $run:\n";

            my $run_result = $level_to_best_results->{$level}->{run_best_results}->[$run];
            print "      Target: $run_result->{target}\n";
            print "      World Position: $run_result->{coordinate}\n";
            print "      Input: $run_result->{input}\n";
            print "      Command: $run_result->{command}\n\n";

            push @found_times, $run_result->{found_time};
        }

        my $mean = mean @found_times;
        my $median = median @found_times;
        my $stddev = stddev @found_times;

        print "    Median time to find solution: " . convert_to_hhmmss($median) . "\n";
        print "    Mean time to find solution: " . convert_to_hhmmss($mean) . " +/- " . convert_to_hhmmss($stddev) . "\n\n";

        print "\033[0m";
    }

    print "  " . ("-" x 198) . "\n\n";

    foreach my $level(sort { $a <=> $b } keys(%{$level_to_best_results})) {
        my $level_result = $level_to_best_results->{$level};

        if (defined $levels_with_solutions{$level} && $levels_with_solutions{$level}->{$fuzzer}) {
            print "\033[32;1m";
        }

        print "  Best result for Level $level (World $level_to_world{$level}):\n";
        print "    Run: $level_result->{run}\n";
        print "    Target: $level_result->{target}\n";
        print "    World Position: $level_result->{coordinate}\n";
        print "    Input: $level_result->{input}\n";
        print "    Command: $level_result->{command}\n\n";

        print "\033[0m";
    }
}

sub parse_to_seconds {
    my $string = $_[0];

    my $days = 0;
    my $hours = 0;
    my $minutes = 0;
    my $seconds = 0;

    #id:000943,src:000896+000849,op:splice,rep:2,+dsf (found after 20 hours 6 minutes and 21 seconds of fuzzing
    $string =~ m/([0-9]+) days/;
    if (defined $1) {
        $days = $1;
    }

    $string =~ m/([0-9]+) hours/;
    if (defined $1) {
        $hours = $1;
    }

    $string =~ m/([0-9]+) minutes/;
    if (defined $1) {
        $minutes = $1;
    }

    $string =~ m/([0-9]+) seconds/;
    if (defined $1) {
        $seconds = $1;
    }

    return ($days * 24 * 60 * 60) + ($hours * 60 * 60) + ($minutes * 60) + $seconds;
}

sub convert_to_hhmmss {
    my $seconds = $_[0];

    my $days = (($seconds / 60) / 60) / 24;
    my $hours = (($seconds / 60) / 60) % 24;
    my $minutes = ($seconds / 60) % 60;
    $seconds = $seconds % 60;

    my $string = "";
    if ($days >= 1) {
        $string = $days > 9 ? "$days" . "d:" : "0$days" . "d:";
    }

    if ($hours > 0 || $minutes > 0 || $seconds > 0) {
        $string .= $hours > 9 ? "$hours" . "h:" : "0$hours" . "h:";
    }

    if ($minutes > 0 || $seconds > 0) {
        $string .= $minutes > 9 ? "$minutes" . "m:" : "0$minutes" . "m:";
    }

    $string .= $seconds > 9 ? "$seconds" . "s" : "0$seconds" . "s";

    return $string;
}
