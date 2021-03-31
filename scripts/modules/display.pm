package display;
use strict;
use warnings;
use open ":std", ":encoding(UTF-8)";
use Text::UnicodeBox;
use Text::UnicodeBox::Control qw(:all);
use Term::ANSIColor;
use Devel::StackTrace;
require Term::Screen;

my $SCREEN_WIDTH = 118;
my $TITLE_ROW = 1;
my $STATS_ROW_START = 3;

my $FIELD_NAME_LENGTH = 17;
my $FIELD_VALUE_LENGTH = 35;
my $WAYPOINT_FIELD_VALUE_LENGTH = 6;

my $title = "sandpuppy deep-state fuzzing";

sub init_display() {
    Term::Screen->new()->clrscr()->curinvis();
}

sub restore_display() {
    Term::Screen->new()->at(25, 0)->curvis();
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

    my $run_time_fmtd = colored(['bold bright_black'], right_align($FIELD_NAME_LENGTH, 'run time'));
    my $overall_delta = colored(['bold white'], left_align($FIELD_VALUE_LENGTH, describe_time_delta(time(), $overall_start_time)));
    my $batch_delta = colored(['bold white'], left_align($FIELD_VALUE_LENGTH, describe_time_delta(time(), $batch_start_time)));

    my $total_paths_fmtd = colored(['bold bright_black'], right_align($FIELD_NAME_LENGTH, 'total paths'));
    my $overall_total_paths = get_formatted_paths_metric($FIELD_VALUE_LENGTH, $overall_stats->{aggregate}->{total_paths});
    my $batch_total_paths = get_formatted_paths_metric($FIELD_VALUE_LENGTH, $batch_stats->{aggregate}->{total_paths});

    my $paths_imported_fmtd = colored(['bold bright_black'], right_align($FIELD_NAME_LENGTH, 'paths imported'));
    my $overall_paths_imported = get_formatted_paths_metric($FIELD_VALUE_LENGTH, $overall_stats->{aggregate}->{paths_imported});
    my $batch_paths_imported = get_formatted_paths_metric($FIELD_VALUE_LENGTH, $batch_stats->{aggregate}->{paths_imported});

    my $paths_found_fmtd = colored(['bold bright_black'], right_align($FIELD_NAME_LENGTH, 'paths found'));
    my $overall_paths_found = get_formatted_paths_metric($FIELD_VALUE_LENGTH, $overall_stats->{aggregate}->{paths_found});
    my $batch_paths_found = get_formatted_paths_metric($FIELD_VALUE_LENGTH, $batch_stats->{aggregate}->{paths_found});

    my $unique_hangs_fmtd = colored(['bold bright_black'], right_align($FIELD_NAME_LENGTH, 'unique hangs'));
    my $overall_unique_hangs = get_formatted_unique_hangs($FIELD_VALUE_LENGTH, $overall_stats->{aggregate}->{unique_hangs});
    my $batch_unique_hangs = get_formatted_unique_hangs($FIELD_VALUE_LENGTH, $batch_stats->{aggregate}->{unique_hangs});

    my $unique_crashes_fmtd = colored(['bold bright_black'], right_align($FIELD_NAME_LENGTH, 'unique crashes'));
    my $overall_unique_crashes = get_formatted_unique_crashes($FIELD_VALUE_LENGTH, $overall_stats->{aggregate}->{unique_crashes});
    my $batch_unique_crashes = get_formatted_unique_crashes($FIELD_VALUE_LENGTH, $batch_stats->{aggregate}->{unique_crashes});

    my $max_depth_fmtd = colored(['bold bright_black'], right_align($FIELD_NAME_LENGTH, 'max depth'));
    my $overall_max_depth = colored(['bold white'], left_align($FIELD_VALUE_LENGTH, $overall_stats->{aggregate}->{max_depth}));
    my $batch_max_depth = colored(['bold white'], left_align($FIELD_VALUE_LENGTH, $batch_stats->{aggregate}->{max_depth}));

    my $number_of_targets_fmtd = colored(['bold bright_black'], right_align($FIELD_NAME_LENGTH, 'number of targets'));
    my $number_of_targets = colored(['bold white'], left_align($FIELD_VALUE_LENGTH, $overall_stats->{aggregate}->{count}));
    my $batch_number_of_targets = colored(['bold white'], left_align($FIELD_VALUE_LENGTH, $batch_stats->{aggregate}->{count}));

    my $finished_targets_fmtd = colored(['bold bright_black'], right_align($FIELD_NAME_LENGTH, 'finished targets'));
    my $finished_targets = get_formatted_finished_targets($FIELD_VALUE_LENGTH, $overall_stats->{aggregate}->{finished}, $overall_stats->{aggregate}->{count});

    my $cycle_fmtd = colored(['bold bright_black'], right_align($FIELD_NAME_LENGTH, 'cycle'));
    my $cycle_value = colored(['bold white'], left_align($FIELD_VALUE_LENGTH, $cycle));

    my $now_processing_fmtd = colored(['bold bright_black'], right_align($FIELD_NAME_LENGTH, 'now processing'));
    my $now_processing = colored(['bold white'], left_align($FIELD_VALUE_LENGTH, "$current_batch of $num_batches"));

    my $blank_label = right_align($FIELD_NAME_LENGTH, '');
    my $blank_value = left_align($FIELD_VALUE_LENGTH, '');

    my $main_total_paths = get_formatted_paths_metric($WAYPOINT_FIELD_VALUE_LENGTH, $overall_stats->{waypoints}->{none}->{total_paths});
    my $main_paths_imported = get_formatted_paths_metric($WAYPOINT_FIELD_VALUE_LENGTH, $overall_stats->{waypoints}->{none}->{paths_imported});
    my $main_paths_found = get_formatted_paths_metric($WAYPOINT_FIELD_VALUE_LENGTH, $overall_stats->{waypoints}->{none}->{paths_found});
    my $main_unique_hangs = get_formatted_unique_hangs($WAYPOINT_FIELD_VALUE_LENGTH, $overall_stats->{waypoints}->{none}->{unique_hangs});
    my $main_unique_crashes = get_formatted_unique_crashes($WAYPOINT_FIELD_VALUE_LENGTH, $overall_stats->{waypoints}->{none}->{unique_crashes});
    my $main_max_depth = colored(['bold white'], left_align($WAYPOINT_FIELD_VALUE_LENGTH, $overall_stats->{waypoints}->{none}->{max_depth}));

    my $waypoints_blank_value = left_align($WAYPOINT_FIELD_VALUE_LENGTH, '');
    my $targets_in_batch_fmtd = colored(['bold bright_black'], right_align($FIELD_NAME_LENGTH, 'targets in batch'));

    my (
        $vvmax_total_paths,
        $vvmax_paths_imported,
        $vvmax_paths_found,
        $vvmax_unique_hangs,
        $vvmax_unique_crashes,
        $vvmax_max_depth,
        $vvmax_num_targets,
        $vvmax_num_targets_in_batch,
        $vvmax_num_finished_targets
    ) = get_formatted_waypoint_targets_stats($overall_stats->{waypoints}, $batch_stats->{waypoints}, 'vvmax');

    my (
        $vvhash_total_paths,
        $vvhash_paths_imported,
        $vvhash_paths_found,
        $vvhash_unique_hangs,
        $vvhash_unique_crashes,
        $vvhash_max_depth,
        $vvhash_num_targets,
        $vvhash_num_targets_in_batch,
        $vvhash_num_finished_targets
    ) = get_formatted_waypoint_targets_stats($overall_stats->{waypoints}, $batch_stats->{waypoints}, 'vvhash');

    my (
        $vvperm_total_paths,
        $vvperm_paths_imported,
        $vvperm_paths_found,
        $vvperm_unique_hangs,
        $vvperm_unique_crashes,
        $vvperm_max_depth,
        $vvperm_num_targets,
        $vvperm_num_targets_in_batch,
        $vvperm_num_finished_targets
    ) = get_formatted_waypoint_targets_stats($overall_stats->{waypoints}, $batch_stats->{waypoints}, 'vvperm');

    $box->add_line(
        BOX_START(style => 'light', top => 'light'), " $run_time_fmtd : $overall_delta ", BOX_RULE(style => 'light'), " $run_time_fmtd : $batch_delta ", BOX_END(),
    );
    $box->add_line(
        BOX_START(style => 'light'), " $total_paths_fmtd : $overall_total_paths " , BOX_RULE(style => 'light'), " $total_paths_fmtd : $batch_total_paths ", BOX_END()
    );
    $box->add_line(
        BOX_START(style => 'light'), " $paths_imported_fmtd : $overall_paths_imported " , BOX_RULE(style => 'light'), " $paths_imported_fmtd : $batch_paths_imported ", BOX_END()
    );
    $box->add_line(
        BOX_START(style => 'light'), " $paths_found_fmtd : $overall_paths_found " , BOX_RULE(style => 'light'), " $paths_found_fmtd : $batch_paths_found ", BOX_END()
    );
    $box->add_line(
        BOX_START(style => 'light'), " $unique_hangs_fmtd : $overall_unique_hangs ", BOX_RULE(style => 'light'), " $unique_hangs_fmtd : $batch_unique_hangs ", BOX_END()
    );
    $box->add_line(
        BOX_START(style => 'light'), " $unique_crashes_fmtd : $overall_unique_crashes ", BOX_RULE(style => 'light'), " $unique_crashes_fmtd : $batch_unique_crashes ", BOX_END()
    );
    $box->add_line(
        BOX_START(style => 'light'), " $max_depth_fmtd : $overall_max_depth ", BOX_RULE(style => 'light'), " $max_depth_fmtd : $batch_max_depth ", BOX_END()
    );
    $box->add_line(
        BOX_START(style => 'light'), " $number_of_targets_fmtd : $number_of_targets ", BOX_RULE(style => 'light'), " $number_of_targets_fmtd : $batch_number_of_targets ", BOX_END()
    );
    $box->add_line(
        BOX_START(style => 'light'), " $finished_targets_fmtd : $finished_targets ", BOX_RULE(style => 'light'), " $now_processing_fmtd : $now_processing ", BOX_END()
    );
    $box->add_line(
        BOX_START(style => 'light', bottom => 'light'), " $cycle_fmtd : $cycle_value ", BOX_RULE(style => 'light'), " $blank_label   $blank_value ", BOX_END()
    );

    $box->add_line(
        BOX_START(style => 'light'), " $total_paths_fmtd : $main_total_paths " , BOX_RULE(style => 'light'), " $total_paths_fmtd : $vvmax_total_paths ", BOX_START(style => 'light'), " $total_paths_fmtd : $vvhash_total_paths " , BOX_RULE(style => 'light'), " $total_paths_fmtd : $vvperm_total_paths ", BOX_END()
    );
     $box->add_line(
        BOX_START(style => 'light'), " $paths_imported_fmtd : $main_paths_imported " , BOX_RULE(style => 'light'), " $paths_imported_fmtd : $vvmax_paths_imported ", BOX_START(style => 'light'), " $paths_imported_fmtd : $vvhash_paths_imported " , BOX_RULE(style => 'light'), " $paths_imported_fmtd : $vvperm_paths_imported ", BOX_END()
    );
    $box->add_line(
        BOX_START(style => 'light'), " $paths_found_fmtd : $main_paths_found " , BOX_RULE(style => 'light'), " $paths_found_fmtd : $vvmax_paths_found ", BOX_START(style => 'light'), " $paths_found_fmtd : $vvhash_paths_found " , BOX_RULE(style => 'light'), " $paths_found_fmtd : $vvperm_paths_found ", BOX_END()
    );
    $box->add_line(
        BOX_START(style => 'light'), " $unique_hangs_fmtd : $main_unique_hangs " , BOX_RULE(style => 'light'), " $unique_hangs_fmtd : $vvmax_unique_hangs ", BOX_START(style => 'light'), " $unique_hangs_fmtd : $vvhash_unique_hangs " , BOX_RULE(style => 'light'), " $unique_hangs_fmtd : $vvperm_unique_hangs ", BOX_END()
    );
    $box->add_line(
        BOX_START(style => 'light'), " $unique_crashes_fmtd : $main_unique_crashes " , BOX_RULE(style => 'light'), " $unique_crashes_fmtd : $vvmax_unique_crashes ", BOX_START(style => 'light'), " $unique_crashes_fmtd : $vvhash_unique_crashes " , BOX_RULE(style => 'light'), " $unique_crashes_fmtd : $vvperm_unique_crashes ", BOX_END()
    );
    $box->add_line(
        BOX_START(style => 'light'), " $max_depth_fmtd : $main_max_depth " , BOX_RULE(style => 'light'), " $max_depth_fmtd : $vvmax_max_depth ", BOX_START(style => 'light'), " $max_depth_fmtd : $vvhash_max_depth " , BOX_RULE(style => 'light'), " $max_depth_fmtd : $vvperm_max_depth ", BOX_END()
    );
    $box->add_line(
        BOX_START(style => 'light'), " $blank_label   $waypoints_blank_value " , BOX_RULE(style => 'light'), " $number_of_targets_fmtd : $vvmax_num_targets ", BOX_START(style => 'light'), " $number_of_targets_fmtd : $vvhash_num_targets " , BOX_RULE(style => 'light'), " $number_of_targets_fmtd : $vvperm_num_targets ", BOX_END()
    );
    $box->add_line(
        BOX_START(style => 'light'), " $blank_label   $waypoints_blank_value " , BOX_RULE(style => 'light'), " $targets_in_batch_fmtd : $vvmax_num_targets_in_batch ", BOX_START(style => 'light'), " $targets_in_batch_fmtd : $vvhash_num_targets_in_batch " , BOX_RULE(style => 'light'), " $targets_in_batch_fmtd : $vvperm_num_targets_in_batch ", BOX_END()
    );
    $box->add_line(
        BOX_START(style => 'light', bottom => 'light'), " $blank_label   $waypoints_blank_value " , BOX_RULE(style => 'light'), " $finished_targets_fmtd : $vvmax_num_finished_targets ", BOX_RULE(style => 'light'), " $finished_targets_fmtd : $vvhash_num_finished_targets " , BOX_RULE(style => 'light'), " $finished_targets_fmtd : $vvperm_num_finished_targets ", BOX_END()
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

    $screen->at($STATS_ROW_START + 11, 2)->puts(colored(['bold cyan'], 'main results'));
    $screen->at($STATS_ROW_START + 11, 31)->puts(colored(['bold cyan'], 'vvmax results'));
    $screen->at($STATS_ROW_START + 11, 60)->puts(colored(['bold cyan'], 'vvhash results'));
    $screen->at($STATS_ROW_START + 11, 89)->puts(colored(['bold cyan'], 'vvperm results'));
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

sub get_formatted_waypoint_targets_stats {
    my $overall_waypoints_stats = $_[0];
    my $batch_waypoints_stats = $_[1];
    my $waypoint = $_[2];

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
        get_formatted_paths_metric($WAYPOINT_FIELD_VALUE_LENGTH, $total_paths),
        get_formatted_paths_metric($WAYPOINT_FIELD_VALUE_LENGTH, $paths_imported),
        get_formatted_paths_metric($WAYPOINT_FIELD_VALUE_LENGTH, $paths_found),
        get_formatted_unique_hangs($WAYPOINT_FIELD_VALUE_LENGTH, $unique_hangs),
        get_formatted_unique_crashes($WAYPOINT_FIELD_VALUE_LENGTH, $unique_crashes),
        colored([$max_depth eq "n/a" ? 'bold red': 'bold white'], left_align($WAYPOINT_FIELD_VALUE_LENGTH, $max_depth)),
        colored([$num_targets eq "n/a" ? 'bold red' : 'bold white'], left_align($WAYPOINT_FIELD_VALUE_LENGTH, $num_targets)),
        colored([$num_targets_in_batch eq "n/a" ? 'bold red' : 'bold white'], left_align($WAYPOINT_FIELD_VALUE_LENGTH, $num_targets_in_batch)),
        get_formatted_finished_targets($WAYPOINT_FIELD_VALUE_LENGTH, $num_finished_targets, $num_targets)
    );
}

1;