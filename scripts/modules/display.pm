package display;
use strict;
use warnings FATAL => 'all';
use open ":std", ":encoding(UTF-8)";
use Time::HiRes qw(time);
use Text::UnicodeBox;
use Text::UnicodeBox::Control qw(:all);
use Text::Chart qw(gen_text_chart);
use Term::ANSIColor;
use Devel::StackTrace;
use List::Util qw(sum);
use Data::Dumper;
use POSIX;
require Term::Screen;

my $SCREEN_WIDTH = 118;
my $TITLE_ROW = 1;
my $STATS_ROW_START = 3;

my $FIELD_NAME_LENGTH = 17;
my $FIELD_VALUE_LENGTH = 35;
my $WAYPOINT_FIELD_VALUE_LENGTH = 6;

my @sparks = map { chr } 0x2581 .. 0x2588;

my %waypoint_to_color = (
    vvmax  => "ansi172",
    vvhash => "ansi179",
    vvperm => "ansi110"
);

my $title = "sandpuppy deep-state fuzzing";

sub init_display() {
    Term::Screen->new()->clrscr()->curinvis();
}

sub restore_display() {
    Term::Screen->new()->at(41, 0)->curvis();
}

sub display_stats {
    my $subject = $_[0];
    my $overall_start_time = $_[1];
    my $batch_start_time = $_[2];
    my $cycle = $_[3];
    my $current_batch = $_[4];
    my $num_batches = $_[5];
    my $overall_stats = $_[6];
    my $batch_stats = $_[7];

    my $screen = Term::Screen->new();
    my $title_pad = ($SCREEN_WIDTH - length("$title ($subject)")) / 2;
    $screen->at($TITLE_ROW, $title_pad)->puts(colored(['bold bright_yellow'], $title) . " " . colored(['bold bright_green'], "($subject)"));

    my $box = Text::UnicodeBox->new();

    my $current_time = time();

    my $run_time_label = colored(['bold bright_blue'], right_align($FIELD_NAME_LENGTH, 'run time'));
    my $overall_delta = colored(['bold white'], left_align($FIELD_VALUE_LENGTH, describe_time_delta($current_time, $overall_start_time)));
    my $batch_delta = colored(['bold white'], left_align($FIELD_VALUE_LENGTH, describe_time_delta($current_time, $batch_start_time)));

    my $last_new_path_label = colored(['bold bright_blue'], right_align($FIELD_NAME_LENGTH, 'last new path'));
    my $overall_last_new_path = get_formatted_last_new_path($current_time, $overall_stats->{aggregate}->{last_new_path_found});
    my $batch_last_new_path = get_formatted_last_new_path($current_time, $batch_stats->{aggregate}->{last_new_path_found});

    my $total_paths_label = colored(['bold bright_blue'], right_align($FIELD_NAME_LENGTH, 'total paths'));
    my $overall_total_paths = get_formatted_paths_metric($FIELD_VALUE_LENGTH, $overall_stats->{aggregate}->{total_paths});
    my $batch_total_paths = get_formatted_paths_metric($FIELD_VALUE_LENGTH, $batch_stats->{aggregate}->{total_paths});

    my $paths_imported_label = colored(['bold bright_blue'], right_align($FIELD_NAME_LENGTH, 'paths imported'));
    my $overall_paths_imported = get_formatted_paths_metric($FIELD_VALUE_LENGTH, $overall_stats->{aggregate}->{paths_imported});
    my $batch_paths_imported = get_formatted_paths_metric($FIELD_VALUE_LENGTH, $batch_stats->{aggregate}->{paths_imported});

    my $paths_found_label = colored(['bold bright_blue'], right_align($FIELD_NAME_LENGTH, 'paths found'));
    my $overall_paths_found = get_formatted_paths_metric($FIELD_VALUE_LENGTH, $overall_stats->{aggregate}->{paths_found});
    my $batch_paths_found = get_formatted_paths_metric($FIELD_VALUE_LENGTH, $batch_stats->{aggregate}->{paths_found});

    my $unique_hangs_label = colored(['bold bright_blue'], right_align($FIELD_NAME_LENGTH, 'unique hangs'));
    my $overall_unique_hangs = get_formatted_unique_hangs($FIELD_VALUE_LENGTH, $overall_stats->{aggregate}->{unique_hangs});
    my $batch_unique_hangs = get_formatted_unique_hangs($FIELD_VALUE_LENGTH, $batch_stats->{aggregate}->{unique_hangs});

    my $unique_crashes_label = colored(['bold bright_blue'], right_align($FIELD_NAME_LENGTH, 'unique crashes'));
    my $overall_unique_crashes = get_formatted_unique_crashes($FIELD_VALUE_LENGTH, $overall_stats->{aggregate}->{unique_crashes});
    my $batch_unique_crashes = get_formatted_unique_crashes($FIELD_VALUE_LENGTH, $batch_stats->{aggregate}->{unique_crashes});

    my $max_depth_label = colored(['bold bright_blue'], right_align($FIELD_NAME_LENGTH, 'max depth'));
    my $overall_max_depth = colored(['bold white'], left_align($FIELD_VALUE_LENGTH, $overall_stats->{aggregate}->{max_depth}));
    my $batch_max_depth = colored(['bold white'], left_align($FIELD_VALUE_LENGTH, $batch_stats->{aggregate}->{max_depth}));

    my $number_of_targets_label = colored(['bold bright_blue'], right_align($FIELD_NAME_LENGTH, 'number of targets'));
    my $number_of_targets = colored(['bold white'], left_align($FIELD_VALUE_LENGTH, $overall_stats->{aggregate}->{count}));
    my $batch_number_of_targets = colored(['bold white'], left_align($FIELD_VALUE_LENGTH, $batch_stats->{aggregate}->{count}));

    my $finished_targets_label = colored(['bold bright_blue'], right_align($FIELD_NAME_LENGTH, 'finished targets'));
    my $finished_targets = get_formatted_finished_targets($FIELD_VALUE_LENGTH, $overall_stats->{aggregate}->{finished}, $overall_stats->{aggregate}->{count});

    my $cycle_label = colored(['bold bright_blue'], right_align($FIELD_NAME_LENGTH, 'cycle'));
    my $cycle_value = colored(['bold white'], left_align($FIELD_VALUE_LENGTH, $cycle));

    my $current_batch_label = colored(['bold bright_blue'], right_align($FIELD_NAME_LENGTH, 'current batch'));
    my $current_batch_of_total = colored(['bold white'], left_align($FIELD_VALUE_LENGTH, "$current_batch of $num_batches"));

    my $average_execs_per_sec_label = colored(['bold bright_blue'], right_align($FIELD_NAME_LENGTH, 'avg execs/s'));
    my $average_execs_per_sec_with_graph = get_formatted_series_average_with_graph(
        $FIELD_VALUE_LENGTH,
        $batch_stats->{aggregate}->{execs_per_sec},
        "execs_per_sec",
        \&get_colored_execs_per_sec
    );

    my $average_path_progress_label = colored(['bold bright_blue'], right_align($FIELD_NAME_LENGTH, 'avg path progress'));
    my $average_path_progress_with_graph = get_formatted_series_average_with_graph(
        $FIELD_VALUE_LENGTH,
        $batch_stats->{aggregate}->{path_progress},
        "path_progress",
        \&get_colored_path_progress
    );

    my $average_cycles_done_label = colored(['bold bright_blue'], right_align($FIELD_NAME_LENGTH, 'avg cycles done'));
    my $average_cycles_done_with_graph = get_formatted_series_average_with_graph(
        $FIELD_VALUE_LENGTH,
        $batch_stats->{aggregate}->{cycles_done},
        "cycles_done"
    );

    my $blank_label = right_align($FIELD_NAME_LENGTH, '');
    my $blank_value = left_align($FIELD_VALUE_LENGTH, '');

    my $vanilla_last_new_path = get_formatted_last_new_path($current_time, $overall_stats->{waypoints}->{none}->{last_new_path_found});
    my $vanilla_total_paths = get_formatted_paths_metric($FIELD_VALUE_LENGTH, $overall_stats->{waypoints}->{none}->{total_paths});
    my $vanilla_paths_imported = get_formatted_paths_metric($FIELD_VALUE_LENGTH, $overall_stats->{waypoints}->{none}->{paths_imported});
    my $vanilla_paths_found = get_formatted_paths_metric($FIELD_VALUE_LENGTH, $overall_stats->{waypoints}->{none}->{paths_found});
    my $vanilla_unique_hangs = get_formatted_unique_hangs($FIELD_VALUE_LENGTH, $overall_stats->{waypoints}->{none}->{unique_hangs});
    my $vanilla_unique_crashes = get_formatted_unique_crashes($FIELD_VALUE_LENGTH, $overall_stats->{waypoints}->{none}->{unique_crashes});
    my $vanilla_max_depth = colored(['bold white'], left_align($FIELD_VALUE_LENGTH, $overall_stats->{waypoints}->{none}->{max_depth}));

    my $waypoints_blank_value = left_align($FIELD_VALUE_LENGTH, '');
    my $targets_in_batch_label = colored(['bold bright_blue'], right_align($FIELD_NAME_LENGTH, 'targets in batch'));

    my (
        $vvmax_last_new_path,
        $vvmax_total_paths,
        $vvmax_paths_imported,
        $vvmax_paths_found,
        $vvmax_unique_hangs,
        $vvmax_unique_crashes,
        $vvmax_max_depth,
        $vvmax_num_targets,
        $vvmax_num_targets_in_batch,
        $vvmax_num_finished_targets
    ) = get_formatted_waypoint_targets_stats($current_time, $overall_stats->{waypoints}, $batch_stats->{waypoints}, 'vvmax');

    my (
        $vvhash_last_new_path,
        $vvhash_total_paths,
        $vvhash_paths_imported,
        $vvhash_paths_found,
        $vvhash_unique_hangs,
        $vvhash_unique_crashes,
        $vvhash_max_depth,
        $vvhash_num_targets,
        $vvhash_num_targets_in_batch,
        $vvhash_num_finished_targets
    ) = get_formatted_waypoint_targets_stats($current_time, $overall_stats->{waypoints}, $batch_stats->{waypoints}, 'vvhash');

    my (
        $vvperm_last_new_path,
        $vvperm_total_paths,
        $vvperm_paths_imported,
        $vvperm_paths_found,
        $vvperm_unique_hangs,
        $vvperm_unique_crashes,
        $vvperm_max_depth,
        $vvperm_num_targets,
        $vvperm_num_targets_in_batch,
        $vvperm_num_finished_targets
    ) = get_formatted_waypoint_targets_stats($current_time, $overall_stats->{waypoints}, $batch_stats->{waypoints}, 'vvperm');

    # Overall and batch stats
    $box->add_line(
        BOX_START(style => 'light', top => 'light'), " $run_time_label : $overall_delta ", BOX_RULE(style => 'light'), " $run_time_label : $batch_delta ", BOX_END(),
    );
    $box->add_line(
        BOX_START(style => 'light'), " $last_new_path_label : $overall_last_new_path " , BOX_RULE(style => 'light'), " $last_new_path_label : $batch_last_new_path ", BOX_END()
    );
    $box->add_line(
        BOX_START(style => 'light'), " $total_paths_label : $overall_total_paths " , BOX_RULE(style => 'light'), " $total_paths_label : $batch_total_paths ", BOX_END()
    );
    $box->add_line(
        BOX_START(style => 'light'), " $paths_imported_label : $overall_paths_imported " , BOX_RULE(style => 'light'), " $paths_imported_label : $batch_paths_imported ", BOX_END()
    );
    $box->add_line(
        BOX_START(style => 'light'), " $paths_found_label : $overall_paths_found " , BOX_RULE(style => 'light'), " $paths_found_label : $batch_paths_found ", BOX_END()
    );
    $box->add_line(
        BOX_START(style => 'light'), " $unique_hangs_label : $overall_unique_hangs ", BOX_RULE(style => 'light'), " $unique_hangs_label : $batch_unique_hangs ", BOX_END()
    );
    $box->add_line(
        BOX_START(style => 'light'), " $unique_crashes_label : $overall_unique_crashes ", BOX_RULE(style => 'light'), " $unique_crashes_label : $batch_unique_crashes ", BOX_END()
    );
    $box->add_line(
        BOX_START(style => 'light'), " $max_depth_label : $overall_max_depth ", BOX_RULE(style => 'light'), " $max_depth_label : $batch_max_depth ", BOX_END()
    );
    $box->add_line(
        BOX_START(style => 'light'), " $number_of_targets_label : $number_of_targets ", BOX_RULE(style => 'light'), " $number_of_targets_label : $batch_number_of_targets ", BOX_END()
    );
    $box->add_line(
        BOX_START(style => 'light'), " $finished_targets_label : $finished_targets ", BOX_RULE(style => 'light'), " $current_batch_label : $current_batch_of_total ", BOX_END()
    );
    $box->add_line(
        BOX_START(style => 'light'), " $cycle_label : $cycle_value ", BOX_RULE(style => 'light'), " $average_execs_per_sec_label : $average_execs_per_sec_with_graph ", BOX_END()
    );
    $box->add_line(
        BOX_START(style => 'light'), " $blank_label   $blank_value ", BOX_RULE(style => 'light'), " $average_path_progress_label : $average_path_progress_with_graph ", BOX_END()
    );
    $box->add_line(
        BOX_START(style => 'light', bottom => 'light'), " $blank_label   $blank_value ", BOX_RULE(style => 'light'), " $average_cycles_done_label : $average_cycles_done_with_graph ", BOX_END()
    );

    # Vanilla and vvmax stats
    $box->add_line(
        BOX_START(style => 'light'), " $last_new_path_label : $vanilla_last_new_path " , BOX_RULE(style => 'light'), " $last_new_path_label : $vvmax_last_new_path ", BOX_END()
    );
    $box->add_line(
        BOX_START(style => 'light'), " $total_paths_label : $vanilla_total_paths " , BOX_RULE(style => 'light'), " $total_paths_label : $vvmax_total_paths ", BOX_END()
    );
     $box->add_line(
        BOX_START(style => 'light'), " $paths_imported_label : $vanilla_paths_imported " , BOX_RULE(style => 'light'), " $paths_imported_label : $vvmax_paths_imported ", BOX_END()
    );
    $box->add_line(
        BOX_START(style => 'light'), " $paths_found_label : $vanilla_paths_found " , BOX_RULE(style => 'light'), " $paths_found_label : $vvmax_paths_found ", BOX_END()
    );
    $box->add_line(
        BOX_START(style => 'light'), " $unique_hangs_label : $vanilla_unique_hangs " , BOX_RULE(style => 'light'), " $unique_hangs_label : $vvmax_unique_hangs ", BOX_END()
    );
    $box->add_line(
        BOX_START(style => 'light'), " $unique_crashes_label : $vanilla_unique_crashes " , BOX_RULE(style => 'light'), " $unique_crashes_label : $vvmax_unique_crashes ", BOX_END()
    );
    $box->add_line(
        BOX_START(style => 'light'), " $max_depth_label : $vanilla_max_depth " , BOX_RULE(style => 'light'), " $max_depth_label : $vvmax_max_depth ", BOX_END()
    );
    $box->add_line(
        BOX_START(style => 'light'), " $blank_label   $waypoints_blank_value " , BOX_RULE(style => 'light'), " $number_of_targets_label : $vvmax_num_targets ", BOX_END()
    );
    $box->add_line(
        BOX_START(style => 'light'), " $blank_label   $waypoints_blank_value " , BOX_RULE(style => 'light'), " $targets_in_batch_label : $vvmax_num_targets_in_batch ", BOX_END()
    );
    $box->add_line(
        BOX_START(style => 'light', bottom => 'light'), " $blank_label   $waypoints_blank_value " , BOX_RULE(style => 'light'), " $finished_targets_label : $vvmax_num_finished_targets ", BOX_END()
    );

    # vvhash and vvperm stats
    $box->add_line(
        BOX_START(style => 'light'), " $last_new_path_label : $vvhash_last_new_path " , BOX_RULE(style => 'light'), " $last_new_path_label : $vvperm_last_new_path ", BOX_END()
    );
    $box->add_line(
        BOX_START(style => 'light'), " $total_paths_label : $vvhash_total_paths " , BOX_RULE(style => 'light'), " $total_paths_label : $vvperm_total_paths ", BOX_END()
    );
    $box->add_line(
        BOX_START(style => 'light'), " $paths_imported_label : $vvhash_paths_imported " , BOX_RULE(style => 'light'), " $paths_imported_label : $vvperm_paths_imported ", BOX_END()
    );
    $box->add_line(
        BOX_START(style => 'light'), " $paths_found_label : $vvhash_paths_found " , BOX_RULE(style => 'light'), " $paths_found_label : $vvperm_paths_found ", BOX_END()
    );
    $box->add_line(
        BOX_START(style => 'light'), " $unique_hangs_label : $vvhash_unique_hangs " , BOX_RULE(style => 'light'), " $unique_hangs_label : $vvperm_unique_hangs ", BOX_END()
    );
    $box->add_line(
        BOX_START(style => 'light'), " $unique_crashes_label : $vvhash_unique_crashes " , BOX_RULE(style => 'light'), " $unique_crashes_label : $vvperm_unique_crashes ", BOX_END()
    );
    $box->add_line(
        BOX_START(style => 'light'), " $max_depth_label : $vvhash_max_depth " , BOX_RULE(style => 'light'), " $max_depth_label : $vvperm_max_depth ", BOX_END()
    );
    $box->add_line(
        BOX_START(style => 'light'), " $number_of_targets_label : $vvhash_num_targets " , BOX_RULE(style => 'light'), " $number_of_targets_label : $vvperm_num_targets ", BOX_END()
    );
    $box->add_line(
        BOX_START(style => 'light'), " $targets_in_batch_label : $vvhash_num_targets_in_batch " , BOX_RULE(style => 'light'), " $targets_in_batch_label : $vvperm_num_targets_in_batch ", BOX_END()
    );
    $box->add_line(
        BOX_START(style => 'light', bottom => 'light'), " $finished_targets_label : $vvhash_num_finished_targets " , BOX_RULE(style => 'light'), " $finished_targets_label : $vvperm_num_finished_targets ", BOX_END()
    );

    my $lines = $box->render();
    my $row = $STATS_ROW_START;
    foreach my $line (split /\n/, $lines) {
        $screen->at($row, 0)->puts($line);
        $row++;
    }

    $screen->at($STATS_ROW_START, 2)->puts(colored(['bold cyan'], 'overall results'));
    $screen->at($STATS_ROW_START, 60)->puts(colored(['bold cyan'], 'batch results'));
    $screen->at($STATS_ROW_START, 2)->puts(colored(['bold cyan'], 'overall results'));

    $screen->at($STATS_ROW_START + 14, 2)->puts(colored(['bold cyan'], 'vanilla afl results'));
    $screen->at($STATS_ROW_START + 14, 60)->puts(colored(['bold cyan'], 'vvmax results'));
    $screen->at($STATS_ROW_START + 25, 2)->puts(colored(['bold cyan'], 'vvhash results'));
    $screen->at($STATS_ROW_START + 25, 60)->puts(colored(['bold cyan'], 'vvperm results'));
}

sub get_formatted_last_new_path {
    my $current_time = $_[0];
    my $last_new_path_found = $_[1];

    if ($last_new_path_found == -1) {
        return colored(['bold red'], left_align($FIELD_VALUE_LENGTH, "n/a"));
    } else {
        return colored(['bold white'], left_align($FIELD_VALUE_LENGTH, describe_time_delta($current_time, $last_new_path_found)));
    }
}

sub get_formatted_paths_metric {
    my $field_value_length = $_[0];
    my $paths_metric = $_[1];

    my $color = $paths_metric ne "n/a" && $paths_metric > 0 ? 'bold white' : 'bold red';
    return colored([$color], left_align($field_value_length, $paths_metric));
}

sub get_formatted_unique_hangs {
    my $field_value_length = $_[0];
    my $unique_hangs = $_[1];

    my $color = $unique_hangs eq "n/a" ? 'bold red' :
                                          $unique_hangs > 0 ? 'bold yellow' : 'bold white';
    return colored([$color], left_align($field_value_length, $unique_hangs));
}

sub get_formatted_unique_crashes {
    my $field_value_length = $_[0];
    my $unique_crashes = $_[1];

    my $color = $unique_crashes eq "n/a" || $unique_crashes > 0 ? 'bold red' : 'bold white';
    return colored([$color], left_align($field_value_length, $unique_crashes));
}

sub get_formatted_finished_targets {
    my $field_value_length = $_[0];
    my $num_finished_targets = $_[1];
    my $num_targets = $_[2];

    if ($num_finished_targets eq "n/a") {
        return colored(['bold red'], left_align($field_value_length, $num_finished_targets));
    }

    my $percentage = ($num_finished_targets / $num_targets) * 100;
    my $color = ($percentage < 50) ? 'bold white' :
        ($percentage < 80) ? 'bold yellow' : 'bold green';
    return colored([$color], left_align($field_value_length, $num_finished_targets));
}

sub get_formatted_series_average_with_graph {
    my $field_value_length = $_[0];
    my @series = @{$_[1]};
    my $series_name = $_[2];
    my $value_colorizer = $_[3];

    my $series_average = calculate_series_average(\@series, $series_name);
    my $colored_average = $value_colorizer ? $value_colorizer->($series_average) : sprintf("%.2f", $series_average);
    my $sparkline = get_sparkline_for_aggregate_series(\@series, $series_name);

    my $graph_right_pad = POSIX::floor($field_value_length / 2) - POSIX::floor(scalar @series / 2);
    my $graph_left_pad = $graph_right_pad - length(sprintf("%.2f", $series_average));
    return $colored_average . (" " x $graph_left_pad) . $sparkline . (" " x $graph_right_pad);
}

sub get_colored_execs_per_sec {
    my $execs_per_sec = sprintf("%.2f", $_[0]);
    my $color = ($execs_per_sec >= 100) ? 'bold green' :
        ($execs_per_sec >= 50) ? 'bold yellow' : 'bold red';
    return colored([$color],  $execs_per_sec);
}

sub get_colored_path_progress {
    my $path_progress = sprintf("%.2f", $_[0]);
    my $color = ($path_progress >= 80) ? 'bold green' :
        ($path_progress >= 50) ? 'bold yellow' : 'bold red';
    return colored([$color], $path_progress);
}

sub get_formatted_waypoint_targets_stats {
    my $current_time = $_[0];
    my $overall_waypoints_stats = $_[1];
    my $batch_waypoints_stats = $_[2];
    my $waypoint = $_[3];

    my $last_new_path_found = $batch_waypoints_stats->{$waypoint} ? $batch_waypoints_stats->{$waypoint}->{last_new_path_found} : -1;
    my $total_paths = $overall_waypoints_stats->{$waypoint} ? $overall_waypoints_stats->{$waypoint}->{total_paths} : "n/a";
    my $paths_imported = $overall_waypoints_stats->{$waypoint} ? $overall_waypoints_stats->{$waypoint}->{paths_imported} : "n/a";
    my $paths_found = $overall_waypoints_stats->{$waypoint} ? $overall_waypoints_stats->{$waypoint}->{paths_found} : "n/a";
    my $unique_hangs = $overall_waypoints_stats->{$waypoint} ? $overall_waypoints_stats->{$waypoint}->{unique_hangs} : "n/a";
    my $unique_crashes = $overall_waypoints_stats->{$waypoint} ? $overall_waypoints_stats->{$waypoint}->{unique_crashes} : "n/a";
    my $max_depth = $overall_waypoints_stats->{$waypoint} ? $overall_waypoints_stats->{$waypoint}->{max_depth} : "n/a";
    my $num_targets = $overall_waypoints_stats->{$waypoint} ? $overall_waypoints_stats->{$waypoint}->{count} : "n/a";
    my $num_targets_in_batch = $batch_waypoints_stats->{$waypoint} ? $batch_waypoints_stats->{$waypoint}->{count} : "n/a";
    my $num_finished_targets = $overall_waypoints_stats->{$waypoint} ? $overall_waypoints_stats->{$waypoint}->{finished} : "n/a";

    return (
        get_formatted_last_new_path($current_time, $last_new_path_found),
        get_formatted_paths_metric($FIELD_VALUE_LENGTH, $total_paths),
        get_formatted_paths_metric($FIELD_VALUE_LENGTH, $paths_imported),
        get_formatted_paths_metric($FIELD_VALUE_LENGTH, $paths_found),
        get_formatted_unique_hangs($FIELD_VALUE_LENGTH, $unique_hangs),
        get_formatted_unique_crashes($FIELD_VALUE_LENGTH, $unique_crashes),
        colored([$max_depth eq "n/a" ? 'bold red': 'bold white'], left_align($FIELD_VALUE_LENGTH, $max_depth)),
        colored([$num_targets eq "n/a" ? 'bold red' : 'bold white'], left_align($FIELD_VALUE_LENGTH, $num_targets)),
        colored([$num_targets_in_batch eq "n/a" ? 'bold red' : 'bold white'], left_align($FIELD_VALUE_LENGTH, $num_targets_in_batch)),
        get_formatted_finished_targets($FIELD_VALUE_LENGTH, $num_finished_targets, $num_targets)
    );
}

sub calculate_series_average {
    my @series = @{$_[0]};
    my $series_name = $_[1];
    return (sum map { $_->{$series_name} } @series) / (scalar @series);
}

sub right_align {
    my $field_length = $_[0];
    my $string = $_[1];
    return (" " x ($field_length - length($string))) . $string;
}

sub left_align {
    my $field_length = $_[0];
    my $string = $_[1];
    return $string . (" " x ($field_length - length($string)));
}

sub describe_time_delta {
    my $current_time = $_[0];
    my $event_time = $_[1];

    my $delta = $current_time - $event_time;
    my $t_d = POSIX::floor($delta / 60 / 60 / 24);
    my $t_h = ($delta / 60 / 60) % 24;
    my $t_m = ($delta / 60) % 60;
    my $t_s = $delta % 60;

    if ($t_m < 10) {
        $t_m = "0$t_m";
    }

    if ($t_s < 10) {
        $t_s = "0$t_s";
    }

    return "$t_d days, $t_h hrs, $t_m min, $t_s sec";
}

sub get_sparkline_for_aggregate_series {
    my @series = @{$_[0]};
    my $series_name = $_[1];

    my @data = map { $_->{$series_name} } @series;
    my @colors = map { $waypoint_to_color{$_} } map { $_->{waypoints} } @series;
    return sparkline(\@data, \@colors, $series_name eq "path_progress" ? 100 : undef, $series_name eq "path_progress" ? 0 : undef);
}

# Adapted from https://rosettacode.org/wiki/Sparkline_in_unicode#Perl
sub sparkline {
    my @data = @{$_[0]};
    my @colors = @{$_[1]};
    my $provided_max = $_[2];
    my $provided_min = $_[3];

    my ($min, $max) = ($data[0]) x 2;
    if (scalar @data > 1) {
        for (@data[1..$#data]) {
            if    ($_ < $min) { $min = $_ }
            elsif ($_ > $max) { $max = $_ }
        }
    }

    if (defined $provided_max) {
        $max = $provided_max;
    }

    if (defined $provided_min) {
        $min = $provided_min;
    }

    my $sparkline = "";
    for (my $i = 0; $i < scalar @data; $i++) {
        my $element = $data[$i];
        my $color = $colors[$i];

        my $denominator = $max == $min ? 1 : $max - $min;
        my $height = int(($element - $min) / $denominator * @sparks);
        $height = $#sparks - 1 if $height >= $#sparks; # So that there is a small separation when stacking graphs

        if(!$sparks[$height]) {
            Term::Screen->new()->at(30, 0)->puts("No sparks for a height of $height and total num is $#sparks");
        }
        $sparkline .= colored([$color], $sparks[$height]);
    }

    return $sparkline;
}

1;