#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';
use File::Path qw(make_path);
use File::Basename;
use Cpanel::JSON::XS;

my $codec = Cpanel::JSON::XS->new->ascii->pretty->allow_nonref;

my $SCRIPT_NAME = basename $0;
my $BASE_PATH = "/mnt/vivin-nfs";
my $STATE_DIR = "/home/vivin/.script-state/$SCRIPT_NAME/space-eval";
if (! -d $BASE_PATH) {
    $BASE_PATH = "/media/2tb/phd-workspace/nfs";
    $STATE_DIR = "/media/2tb/phd-workspace/script-data/$SCRIPT_NAME/space-eval";
}

make_path $STATE_DIR;

my $RUN_DIR = "$BASE_PATH/vivin/smartdsf/jsoncpp/results/space-eval";
my $RESULTS_DIR = "$RUN_DIR/aggregated";
make_path $RESULTS_DIR;

my $NEW_SEEDS = "$RUN_DIR/new-seeds";
make_path $NEW_SEEDS;

print "Processing jsoncpp results for fuzzer sandpuppy...\n\n";

my $fuzzer_dir = "$RUN_DIR/sandpuppy-sync";

chomp(my @sessions = `grep "^[^- ]" $RUN_DIR/id_to_pod_name_and_target.yml | sed -e 's,:,,'`);
my $num_sessions = scalar @sessions;
my $i = 0;
foreach my $session(@sessions) {
    my $dir = "$fuzzer_dir/$session/queue";
    next if ! -e -d $dir;

    print "[" . (++$i) . "/$num_sessions] Processing inputs in session $session...\n";

    chomp (my $num_files = `ls -f $dir | grep -v "^\\." | grep -v ",sync:" | wc -l`);
    my $count = 0;
    open FILES, "ls -f $dir |";
    while (my $file = <FILES>) {
        chomp $file;

        if ($file =~ /id:/ && $file !~ /,sync:/) {
            my $state_file = "$STATE_DIR/$session-$file";
            if (-e -f $state_file) {
                print "Skipping input " . (++$count) . " of $num_files (already processed)\r";
                next;
            }

            system "/home/vivin/Projects/phd/resources/readjson $dir/$file 2>&1 >/dev/null";
            if ($? != 0) {
                print "Skipping input " . (++$count) . " of $num_files (invalid json)     \r";
            } else {
                print "Copying input " . (++$count) . " of $num_files                   \r";
                system "cp $dir/$file $NEW_SEEDS/$session-$file"
            }

            system "touch $state_file";
        }
    }
    close FILES;
}