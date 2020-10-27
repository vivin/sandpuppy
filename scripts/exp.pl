#!/usr/bin/perl

# hierarchy:
#  expname
#   subject
#    binary
#     <context>/file
#    results
#     <context>/
#
#    default context for binary is "default".
#    default context for results is "default".
#
#    context can be whatever you want. it's just a way to segregate stuff within an experiment.
#
#    for wejon, the idea is you start with context "default" or maybe you call it something. whatever.
#    then the results would also be in a dir with the same context name. then we will build a binary based off that run
#    so we could call the new context default.ijon (meaning the binary was created using data from default run of ijon).
#    then results would also be default.ijon. maybe we have default.ijon0, default.ijon1 etc. for diff stages. 
#



use strict;
use warnings;
use Log::Simple::Color;
use File::Path qw(make_path);

  my $log = Log::Simple::Color->new;

  my $NAMED_PIPE_PATH = "/tmp/vvdump";

  my $BASEPATH = glob "~/Projects/phd";
  my $BASEWORKSPACEPATH = "$BASEPATH/workspace";
  my $TOOLS = "$BASEPATH/tools";
  my $RESOURCES = "$BASEPATH/resources";
  my $SUBJECTS = "$RESOURCES/subjects";

  my $FUZZ_FACTORY = "$TOOLS/FuzzFactory";

  my $builders = {
      "infantheap" => \&build_infantheap
  };

  my $fuzzers = {
      "infantheap" => \&fuzz_infantheap
  };

  if (scalar @ARGV < 5) {
      die "You need at least some arguments. Maybe I will document them some day.\n";
  }

  my $experiment_name = $ARGV[0];
  my $subject = $ARGV[1]; # this single param should let me identify source dir for building
  my $waypoints = $ARGV[2];
  my $context = $ARGV[3];
  my $command = $ARGV[4];

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

  if ($ARGV[4] eq "build") {
      if (!$builders->{$subject}) {
          die "No builder for $subject.";
      }

      &{$builders->{$subject}}($experiment_name, $subject, $context, $waypoints);
  } elsif ($ARGV[4] eq "fuzz") {
      if ($ARGV[5] ne "using") {
          die "Expected \"using\":\n  $0 $experiment_name $subject $context $waypoints $command using <binary-context>";
      }

      if (!$ARGV[6]) {
          die "Expected <binary-context>:\n  $0 $experiment_name $subject $context $waypoints $command using <binary-context>";
      }

      &{$fuzzers->{$subject}}($experiment_name, $subject, $context, $waypoints, $ARGV[6], $ARGV[7] eq "resume");
  }

  sub build_infantheap {
      my $experiment_name = $_[0];
      my $subject = $_[1];
      my $context = $_[2];
      my $waypoints = $_[3];

      my $binary_base = "$workspace/binaries";
      my $binary_dir = "";

      if ($context eq "default") {
          my $result = `find $binary_base -type d -name "ver[0-9]" | sed -e 's,.*\\([0-9]\\+\\),\\1,' | sort -r | head -1`;
          if ($result eq "") {
              $result = -1;
          }

          my $new_version = ++$result;

          $binary_dir = "$binary_base/ver$new_version";
      } else {
          $binary_dir = "$binary_base/$context";
      }

      my $binary = "$binary_dir/infantheap";

      if (-d $binary_dir and -e $binary) {
          my $result = `find $binary_dir -type f -name "*backup[0-9]" | sed -e 's,.*\\([0-9]\\+\\),\\1,' | sort -r | head -1`;
          if ($result eq "") {
              $result = -1;
          }

          my $new_version = ++$result;

          $log->info("Backing up existing binary to backup version $new_version");
          system ("cp $binary $binary_dir/infantheap.backup$new_version");
      } elsif (! -d $binary_dir) {
          make_path($binary_dir);
      }

      my $build_command = "$FUZZ_FACTORY/afl-clang-fast -fno-inline-functions -fno-discard-value-names -fno-unroll-loops";

      my $use_asan = ($context =~ /asan/);
      if ($use_asan) {
          $build_command .= " -fsanitize=address";
      }

      my $use_trace_dir = ($waypoints =~ /trace/);
      if ($use_trace_dir) {
          $build_command .= " -trace_directory=$workspace/traces";
      }

      my $use_named_pipe = ($waypoints =~ /vardump/);
      if ($use_named_pipe) {
          # $build_command .= " -named_pipe=$NAMED_PIPE_PATH";
      }
      
      # TODO: have to account for WEJON instrumentation waypoint eventually... similar arg like functions file
      
      my $src_dir = "$SUBJECTS/infantheap";

      $build_command .= " $src_dir/infantheap.c -o $binary_dir/infantheap";

      if ($waypoints ne "none") {
          system "export WAYPOINTS=$waypoints; $build_command";
      } else {
          system $build_command;
      }
  }

  sub fuzz_infantheap {
      my $experiment_name = $_[0];
      my $subject = $_[1];
      my $context = $_[2];
      my $waypoints = $_[3];
      my $binary_context = $_[4];
      my $resume = $_[5];

      my $results_base = "$workspace/results";
      my $results_dir = "$results_base/$context";

      if (!$resume) {
          if (-d $results_dir) {
              my $result = `find $results_base -type d -name "*backup[0-9]" | sed -e 's,.*\\([0-9]\\+\\),\\1,' | sort -r | head -1`;
              if ($result eq "") {
                  $result = -1;
              }

              my $new_version = ++$result;

              $log->info("Backing up existing results directory to backup version $new_version");
              system ("mv $results_dir $results_base/$context.backup$new_version");

          }

          make_path($results_dir);
      } elsif (! -d $results_dir) {
          die "Cannot resume because cannot find results dir at $results_dir";
      }

      my $binary = "$workspace/binaries/$binary_context/infantheap";
      if (! -e $binary) {
          die "Could not find binary for binary context $binary_context at $binary";
      }

      my $fuzz_command = "$FUZZ_FACTORY/afl-fuzz";
      if ($waypoints ne "none") {
          $fuzz_command .= " -p";
      }

      if ($resume) {
          $fuzz_command .= " -i-"
          
      } else {
          my $seeds_directory = "$RESOURCES/seeds/infantheap/non-crashing-asan"; # buffer-overflow breaks things when we have vvdump instrumentation
          $fuzz_command .= " -i $seeds_directory";
      }

      $fuzz_command .= " -o $results_dir -T \"infantheap-$experiment_name-$context\"";

      my $use_trace_dir = ($waypoints =~ /trace/);
      if ($use_trace_dir) {
          $fuzz_command .= " -R $workspace/traces";
      }

      my $use_asan = ($context =~ /asan/);
      if ($use_asan) {
          system "export ASAN_OPTIONS=\"abort_on_error=1:symbolize=0:exitcode=86\"";
          $fuzz_command .= " -m none";
      }

      $fuzz_command .= " $binary";

      system $fuzz_command;
      system "unset ASAN_OPTIONS";
  }
