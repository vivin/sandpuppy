package analysis;
use strict;
use warnings FATAL => 'all';

use File::Basename;
use File::Path qw(make_path);
use File::stat;
use Redis;
use YAML::XS;
use Time::HiRes qw(time);

use utils;

my $BASE_PATH = glob "~/Projects/phd";
my $RESOURCES = "$BASE_PATH/resources";

my $log = Log::Simple::Color->new;
my $redis = Redis->new;
my $fuzz_config = YAML::XS::LoadFile("$RESOURCES/fuzz_config.yml");

sub get_basic_blocks_for_input {
    my $subject = $_[0];
    my $input_file = $_[1];

    my $binary = "$RESOURCES/$fuzz_config->{$subject}->{binary_name}-bbprinter";
    my $command = "$binary $fuzz_config->{$subject}->{argument}";
    $command =~ s/\@\@/$input_file/;

    chomp(my @data = `$command 2> /dev/null | grep \"__#BB#__\" | grep -v $binary | sed 's,__#BB#__: ,,'`);
    my %seen;
    my @basic_blocks = sort(grep !$seen{$_}++, @data);
    return \@basic_blocks;
}

sub check_if_input_processed_successfully {
    my $subject = $_[0];
    my $input_file = $_[1];

    my $binary = "$RESOURCES/$fuzz_config->{$subject}->{binary_name}";
    my $command = "$binary $fuzz_config->{$subject}->{argument}";
    $command =~ s/\@\@/$input_file/;

    system "$command 2>&1 >/dev/null";
    return $? == 0;
}

sub is_coverage_new {
    my $experiment = $_[0];
    my $subject = $_[1];
    my $version = $_[2];
    my $run_name = $_[3];
    my $iteration = $_[4];
    my @basic_blocks = @{$_[5]};

    my $full_subject = $subject . ($version ? "-$version" : "");
    my $key = "$experiment:$full_subject:$run_name-$iteration.coverage";
    my $has_new_coverage = 0;
    foreach my $bb(@basic_blocks) {
        my $result = $redis->sadd($key, $bb);
        if ($has_new_coverage == 0) {
            $has_new_coverage = $result;
        }
    }

    return $has_new_coverage;
}

sub is_session_coverage_new {
    my $experiment = $_[0];
    my $subject = $_[1];
    my $version = $_[2];
    my $run_name = $_[3];
    my $iteration = $_[4];
    my $session = $_[5];
    my @basic_blocks = @{$_[6]};

    my $full_subject = $subject . ($version ? "-$version" : "");
    my $key = "$experiment:$full_subject:$run_name-$iteration:$session.coverage";
    my $has_new_coverage = 0;
    foreach my $bb(@basic_blocks) {
        my $result = $redis->sadd($key, $bb);
        if ($has_new_coverage == 0) {
            $has_new_coverage = $result;
        }
    }

    return $has_new_coverage;
}

sub record_input_coverage {
    my $experiment = $_[0];
    my $subject = $_[1];
    my $version = $_[2];
    my $run_name = $_[3];
    my $iteration = $_[4];
    my $input_file = $_[5];
    my @basic_blocks = @{$_[6]};

    my $full_subject = $subject . ($version ? "-$version" : "");
    my $key = "$experiment:$full_subject:$run_name-$iteration.coverage_over_time";
    my $ctime = stat($input_file)->ctime;
    $redis->sadd($key, "$ctime," . (join ";", @basic_blocks));
}

sub record_session_input_coverage {
    my $experiment = $_[0];
    my $subject = $_[1];
    my $version = $_[2];
    my $run_name = $_[3];
    my $iteration = $_[4];
    my $session = $_[5];
    my $input_file = $_[6];
    my @basic_blocks = @{$_[7]};

    my $full_subject = $subject . ($version ? "-$version" : "");
    my $key = "$experiment:$full_subject:$run_name-$iteration:$session.coverage_over_time";
    my $ctime = stat($input_file)->ctime;
    $redis->sadd($key, "$ctime," . (join ";", @basic_blocks));
}

sub copy_input_for_tracegen {
    my $experiment = $_[0];
    my $subject = $_[1];
    my $version = $_[2];
    my $run_name = $_[3];
    my $iteration = $_[4];
    my $session = $_[5];
    my $input_file = $_[6];

    my $SUBJECT_DIR;
    if (-d "/mnt/vivin-nfs") {
        $SUBJECT_DIR = utils::get_nfs_subject_directory($experiment, $subject, $version);
    } else {
        $SUBJECT_DIR = utils::get_remote_nfs_subject_directory($experiment, $subject, $version);
    }

    my $TRACEGEN_DIR = "$SUBJECT_DIR/results/$run_name-$iteration/tracegen-staging";
    make_path $TRACEGEN_DIR;

    my ($filename, $dir, $ext) = fileparse($input_file);
    system "cp $input_file $TRACEGEN_DIR/$session-$filename";
}

sub copy_input_for_next_iteration_seeds {
    my $experiment = $_[0];
    my $subject = $_[1];
    my $version = $_[2];
    my $run_name = $_[3];
    my $iteration = $_[4];
    my $session = $_[5];
    my $input_file = $_[6];

    my $SUBJECT_DIR;
    if (-d "/mnt/vivin-nfs") {
        $SUBJECT_DIR = utils::get_nfs_subject_directory($experiment, $subject, $version);
    } else {
        $SUBJECT_DIR = utils::get_remote_nfs_subject_directory($experiment, $subject, $version);
    }

    my $SEEDS_DIR = "$SUBJECT_DIR/seeds/$run_name-${\($iteration + 1)}";
    make_path $SEEDS_DIR;

    my ($filename, $dir, $ext) = fileparse($input_file);
    $filename =~ s/,.*$//;

    system "cp $input_file $SEEDS_DIR/$session-$filename";
}

sub iterate_fuzzer_results {
    my $experiment = $_[0];
    my $subject = $_[1];
    my $version = $_[2];
    my $run_name = $_[3];
    my $fuzzer = $_[4];
    my @sessions = @{$_[5]};
    my $handler = $_[6];

    my $full_subject = $subject . ($version ? "-$version" : "");

    my $SUBJECT_DIR;
    if (-d "/mnt/vivin-nfs") {
        $SUBJECT_DIR = utils::get_nfs_subject_directory($experiment, $subject, $version);
    } else {
        $SUBJECT_DIR = utils::get_remote_nfs_subject_directory($experiment, $subject, $version);
    }

    my $processed_files_key = "$experiment:$full_subject:$run_name:$fuzzer.processed_files";
    my $sha512_key = "$experiment:$full_subject:$run_name:$fuzzer.sha512";

    my $FUZZER_DIR = "$SUBJECT_DIR/results/$run_name/$fuzzer-sync";

    my $num_sessions = scalar @sessions;
    my $i = 0;
    foreach my $session(@sessions) {
        my $inputs_dir = "$FUZZER_DIR/$session/queue";
        next if ! -e -d $inputs_dir;

        print "[" . (++$i) . "/$num_sessions] Processing inputs in session $session...\n";

        chomp (my $num_files = `ls -f $inputs_dir | grep -v "^\\." | grep -v ",sync:" | wc -l`);
        my $count = 0;
        open FILES, "ls -f $inputs_dir | grep -v \"^\\.\" | grep -v \",sync:\" | ";
        while (my $file = <FILES>) {
            chomp $file;

            if ($redis->sismember($processed_files_key, "$inputs_dir/$file")) {
                print "Skipping input " . (++$count) . " of $num_files (already processed)      \r";
                next;
            }

            my $ctime = stat("$inputs_dir/$file")->ctime;
            if (time() - $ctime < 45) {
                print "Skipping input " . (++$count) . " of $num_files (file is too new)        \r";
                next;
            }

            # NOTE: It may seem like this will mess up per-session coverage data because we use the same set of seeds
            # NOTE: for each session, which means that we will be ignoring them when processing files in subsequent
            # NOTE: sessions after we process one. However, this is not an issue since we can reconstruct that initial
            # NOTE: coverage by using the calculated overall-coverage from the previous iteration.
            chomp(my $sha512 = `sha512sum $inputs_dir/$file | awk '{ print \$1; }'`);
            if ($redis->sismember($sha512_key, $sha512)) {
                $redis->sadd($processed_files_key, "$inputs_dir/$file");
                print "Skipping input " . (++$count) . " of $num_files (sha512 already seen)    \r";
                next;
            }

            if ($file =~ /id:/) {
                print "Processing input " . (++$count) . " of $num_files                        \r";
                my $start = time();
                $handler->($session, "$inputs_dir/$file");
                my $diff = time() - $start;
                printf "elapsed: %.9f\n", $diff;
            }

            $redis->sadd($processed_files_key, "$inputs_dir/$file");
            $redis->sadd($sha512_key, $sha512);
        }
        close FILES;
    }

    $handler->("__COMPLETED__", "__COMPLETED__");
}

1;