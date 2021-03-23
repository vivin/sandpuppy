package utils;

use strict;
use warnings;
use Log::Simple::Color;
use File::Path qw(make_path);

my $log = Log::Simple::Color->new;
my $BASEPATH = glob "~/Projects/phd";
my $BASEWORKSPACEPATH = "$BASEPATH/workspace";
my $TOOLS = "$BASEPATH/tools";
my $RESOURCES = "$BASEPATH/resources";
my $SUBJECTS = "$BASEPATH/subjects";

sub create_binary_dir_and_backup_existing {
    my $binary_dir = $_[0];
    my $binary_name = $_[1];

    my $binary = "$binary_dir/$binary_name";
    if (-d $binary_dir and -e $binary) {
        my $result = `find $binary_dir -type f -name "*backup[0-9]" | sed -e 's,^.*backup,,' | sort -nr | head -1`;
        if ($result eq "") {
            $result = -1;
        }

        my $new_version = ++$result;

        $log->info("Backing up existing binary to backup version $new_version");
        system ("cp $binary $binary_dir/$binary_name.backup$new_version");
    } elsif (! -d $binary_dir) {
        make_path($binary_dir);
    }
}

sub create_results_dir_and_backup_existing {
    my $results_base = $_[0];
    my $exec_context = $_[1];

    my $results_dir = "$results_base/$exec_context";
    if (-d $results_dir) {
        my $result = `find $results_base -type d -regex '.*$exec_context.backup[0-9]+' | sed -e 's,^.*backup,,' | sort -nr | head -1`;
        if ($result eq "") {
            $result = -1;
        }

        my $new_version = ++$result;

        $log->info("Backing up existing results directory to backup version $new_version");
        system ("mv $results_dir $results_base/$exec_context.backup$new_version");
    }

    make_path($results_dir);
}