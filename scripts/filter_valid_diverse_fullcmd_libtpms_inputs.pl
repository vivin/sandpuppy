#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';
use File::Path qw(make_path);
use Storable qw{lock_store lock_retrieve};

my $BASE_PATH = "/mnt/vivin-nfs";
if (! -d $BASE_PATH) {
    $BASE_PATH = "/media/2tb/phd-workspace/nfs";
}

my $RUN_DIR = "$BASE_PATH/vivin/smartdsf/libtpms/results/di-ec-run";
my $RESULTS_DIR = "$RUN_DIR/aggregated";
make_path $RESULTS_DIR;

my $NEW_SEEDS = "$RUN_DIR/new-seeds";
make_path $NEW_SEEDS;

print "Processing libtpms results for fuzzer sandpuppy...\n\n";

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
            system "/home/vivin/Projects/phd/resources/readtpmc-fullcmd $dir/$file 2>&1 >/dev/null";
            if ($? != 0) {
                print "Skipping input " . (++$count) . " of $num_files (invalid tpm commands)     \r";
            } else {
                print "Copying input " . (++$count) . " of $num_files                         \r";
                system "cp $dir/$file $NEW_SEEDS/$session-$file"
            }
        }
    }
    close FILES;
}