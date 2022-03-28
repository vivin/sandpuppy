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
    0  => "1-1", # solution is when position >= 3142
    2  => "1-2", # 2664 or thereabouts
    3  => "1-3", # 2409
    4  => "1-4", # solution is when position >= 2234
    5  => "2-1", # solution is when position >= 3009 (2, 3 running)
    7  => "2-2", # solution is when position >= 3013
    8  => "2-3", # solution is when position >= 3572
    9  => "2-4", # solution is when position >= 2234
    10 => "3-1", # solution is when position >= 3174 (run 2, 3 ongoing)
    11 => "3-2", # solution is when position >= 3317
    12 => "3-3", # solution is when position >= 2393
    13 => "3-4", # solution is when position >= 2234
    14 => "4-1", # solution is when position >= 3572
    16 => "4-2", # 3556 warp zone. lower is likely for actual solution
    17 => "4-3", # solution is when position >= 2329
    18 => "4-4", # no solution
    19 => "5-1", # solution is when position >= 3158
    20 => "5-2", # solution is when position >= 3174
    21 => "5-3", # solution is when position >= 2409
    22 => "5-4", # solution is when position >= 2234 (or thereabouts)
    23 => "6-1", # solution is when position >= 2951
    24 => "6-2", # solution is when position >= 3429 (run 3 ongoing)
    25 => "6-3", # solution is when position >= 2648
    26 => "6-4", # solution is when position >= 2234 (or thereabouts)
    27 => "7-1", # solution is when position >= 2839
    29 => "7-2", # solution is when position >= 3013
    30 => "7-3", # solution is when position >= 3572
    31 => "7-4", # solution is when position >= 3276 (or thereabouts)
    32 => "8-1", # need 1, 2, 3
    33 => "8-2", # 3429 (1/3)
    34 => "8-3", # solution is when position >= 3397
    35 => "8-4"  # solution is when position >= 4784,4809
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
            max_world_pos    => -1,
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
