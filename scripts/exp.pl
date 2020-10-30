#!/usr/bin/perl

use lib glob "~/Projects/phd/scripts/modules";
use strict;
use warnings;
use Log::Simple::Color;
use File::Path qw(make_path);
use infantheap;
use rarebug;
use vvdprocessor;

  my $log = Log::Simple::Color->new;

  my $BASEPATH = glob "~/Projects/phd";
  my $BASEWORKSPACEPATH = "$BASEPATH/workspace";
  my $TOOLS = "$BASEPATH/tools";
  my $RESOURCES = "$BASEPATH/resources";
  my $SUBJECTS = "$RESOURCES/subjects";

  my $subjects = {
      "infantheap" => {
          "tasks" => {
              "build" => \&infantheap::build,
              "fuzz"  => \&infantheap::fuzz
          }
      },
      "rarebug" => {
          "tasks" => {
              "build" => \&rarebug::build,
              "fuzz"  => \&rarebug::fuzz
          }
      },
  };

  if (scalar @ARGV < 5) {
      die "You need at least some arguments. Maybe I will document them some day.\n";
  }

  my $experiment_name = $ARGV[0];
  my $subject = $ARGV[1]; # this single param should let me identify source dir for building
  my $waypoints = $ARGV[2];
  my $context = $ARGV[3];
  my $task = $ARGV[4];
  my $binary_context = $ARGV[6];

  my $workspace = "$BASEWORKSPACEPATH/$experiment_name/$subject";

  if (! -d $workspace) {
      $log->info("Creating $workspace");
      make_path($workspace);
  }
  
  if (! -d "$workspace/binaries") {
      $log->info("Creating $workspace/binaries");
      make_path("$workspace/binaries");
  }

  if (! -d "$workspace/results") {
      $log->info("Creating $workspace/results");
      make_path("$workspace/results");
  }

  if (! -d "$workspace/traces") {
      $log->info("Creating $workspace/traces");
      make_path("$workspace/traces");
  }

  if (!$subjects->{$subject}) {
      die "No subject named $subject.";
  }

  my $tasks = $subjects->{$subject}->{tasks};

  if ($task eq "build") {
      if (!$tasks->{build}) {
          die "No build task for $subject.";
      }

      &{$tasks->{build}}($experiment_name, $subject, $context, $waypoints);
  } elsif ($task eq "fuzz") {
      if ($ARGV[5] ne "using") {
          die "Expected \"using\":\n  $0 $experiment_name $subject $context $waypoints $task using <binary-context>";
      }

      if (!$ARGV[6]) {
          die "Expected <binary-context>:\n  $0 $experiment_name $subject $context $waypoints $task using <binary-context>";
      }

      if (!$tasks->{fuzz}) {
          die "No fuzz task for $subject.";
      }

      $ENV{"__VVD_EXP_NAME"} = $experiment_name;
      $ENV{"__VVD_SUBJECT"} = $subject;
      $ENV{"__VVD_BIN_CONTEXT"} = $binary_context;
      $ENV{"__VVD_EXEC_CONTEXT"} = $context;

      my $reader_pid = &vvdprocessor::start();

      &{$tasks->{fuzz}}($experiment_name, $subject, $context, $waypoints, $binary_context, 0);

      delete $ENV{"__VVD_EXP_NAME"};
      delete $ENV{"__VVD_SUBJECT"};
      delete $ENV{"__VVD_BIN_CONTEXT"};
      delete $ENV{"__VVD_EXEC_CONTEXT"};

      $log->info("Waiting for vvdump trace processor to finish...");

      waitpid $reader_pid, 0;
  }
