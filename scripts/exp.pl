#!/usr/bin/perl

use lib glob "~/Projects/phd/scripts/modules";
use strict;
use warnings;
use Log::Simple::Color;
use File::Path qw(make_path);
use Time::HiRes qw(time);
use POSIX;
use infantheap;
use rarebug;
use maze;
use libpng;
use readelf;
use libtpms;

  if (! -e "/tmp/vvdump") {
      POSIX::mkfifo("/tmp/vvdump", 0700) or die "Could not create /tmp/vvdump";
  }

my $log = Log::Simple::Color->new;

  my $BASEPATH = glob "~/Projects/phd";
  my $BASEWORKSPACEPATH = "$BASEPATH/workspace";
  my $TOOLS = "$BASEPATH/tools";

  my $subjects = {
      infantheap => {
          tasks => {
              build => \&infantheap::build,
              fuzz  => \&infantheap::fuzz
          },
          fuzz_time => 600
      },
      rarebug => {
          tasks => {
              build => \&rarebug::build,
              fuzz  => \&rarebug::fuzz
          },
          fuzz_time => 600
      },
      maze => {
          tasks => {
              build => \&maze::build,
              fuzz  => \&maze::fuzz
          },
          fuzz_time => 1200
      },
      libpng => {
          tasks => {
              build => \&libpng::build,
              fuzz  => \&libpng::fuzz
          },
          fuzz_time => 14400
      },
      readelf => {
          tasks => {
              build => \&readelf::build,
              fuzz  => \&readelf::fuzz
          },
          fuzz_time => 7200
      },
      libtpms => {
          tasks     => {
              build => \&libtpms::build,
              fuzz  => \&libtpms::fuzz
          },
          fuzz_time => 14400
      }
  };

  if (scalar @ARGV < 5) {
      die "You need at least some arguments. Maybe I will document them some day.\n";
  }

  my $experiment_name = $ARGV[0];
  my $full_subject = $ARGV[1]; # this single param should let me identify source dir for building
  my $original_subject = $full_subject;
  my $subject = $full_subject;
  my $version;
  my $waypoints = $ARGV[2];
  my $context = $ARGV[3];
  my $task = $ARGV[4];
  my $binary_context = $ARGV[6];

  if ($full_subject =~ /:/) {
      ($subject, $version) = split(/:/, $full_subject);
      $full_subject =~ s/:/-/;
  }

  my $workspace = "$BASEWORKSPACEPATH/$experiment_name/$full_subject";

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
      die "No subject named $subject";
  }

  my $tasks = $subjects->{$subject}->{tasks};

  if ($task eq "build") {
      if (!$tasks->{build}) {
          die "No build task for $subject.";
      }

      &{$tasks->{build}}($experiment_name, $subject, $version, $context, $waypoints);
  } elsif ($task eq "fuzz") {
      if ($ARGV[5] ne "using") {
          die "Expected \"using\":\n  $0 $experiment_name $original_subject $context $waypoints $task using <binary-context>";
      }

      if (!$ARGV[6]) {
          die "Expected <binary-context>:\n  $0 $experiment_name $original_subject $context $waypoints $task using <binary-context>";
      }

      if (!$tasks->{fuzz}) {
          die "No fuzz task for $subject.";
      }

      # We are going to start the trace processor. We will start it as a child process and communicate its STDOUT to
      # the parent script.

      if ($binary_context =~ /vvdump/) {

          $ENV{"__VVD_EXP_NAME"} = $experiment_name;
          $ENV{"__VVD_SUBJECT"} = $full_subject;
          $ENV{"__VVD_BIN_CONTEXT"} = $binary_context;
          $ENV{"__VVD_EXEC_CONTEXT"} = $context;

          pipe my $reader, my $writer;
          $writer->autoflush(1);

          my $vvdproc_pid = fork;
          if ($vvdproc_pid) {
              # In the parent process. Here we will start the fuzzer in another child process. The fuzzer STDOUT will still
              # be sent to the parent STDOUT (which we want). Note that after spawning the child fuzzer process, we start
              # reading from the trace processor's STDOUT. We do not print anything from it initially as we want to see the
              # fuzzer output. However, if the fuzzer is stopped (Ctrl-C) it sends out a poison pill trace which the trace
              # processor will read. When it does, it will output a message saying "Fuzzer has shut down". Once we detect
              # this string in the trace processor's STDOUT, we will start printing the trace processor output. The trace
              # processor output tells us how many traces from how many processes remain to be inserted into the db.

              close $writer;
              $SIG{INT} = 'IGNORE';

              my $STARTUP_TIME = 10; # about the time it takes to start up vvdproc and the fuzzer
              my $FUZZ_TIME = $subjects->{$subject}->{fuzz_time} + $STARTUP_TIME;
              my $killed = 0;
              my $start_time = time();
              my $fuzzer_pid = &{$tasks->{fuzz}}($experiment_name, $subject, $version, $context, $waypoints, $binary_context, 0);
              my $start_printing = 0;
              while (<$reader>) {
                  if (!$start_printing) {
                      $start_printing = ($_ =~ /Fuzzer has shut down/);
                  }

                  if (!$killed and time() - $start_time >= $FUZZ_TIME) {
                      kill 'INT', $fuzzer_pid;
                      $killed = 1;
                  }

                  print $_ if $start_printing;
              }

              waitpid $vvdproc_pid, 0;

              delete $ENV{"__VVD_EXP_NAME"};
              delete $ENV{"__VVD_SUBJECT"};
              delete $ENV{"__VVD_BIN_CONTEXT"};
              delete $ENV{"__VVD_EXEC_CONTEXT"};
              delete $ENV{"ASAN_OPTIONS"};
          } else {
              # Start the trace processor using open, and redirect its STDOUT to a file handle (using -|). Write the STDOUT
              # content to $writer, which will send it back to the main script.
              # Also make sure we ignore SIGINT because the processor knows to stop on its own (afl-fuzz sends a poison pill
              # in the trace when it is stopped).

              close $reader;
              $SIG{INT} = 'IGNORE';

              chdir "$TOOLS/vvdproc";
              my $vvdproc = "unbuffer mvn package && unbuffer java -Xms1G -Xmx4G -jar target/vvdproc.jar 2>&1";
              open my $vvdproc_output, "-|", $vvdproc;
              while (<$vvdproc_output>) {
                  print $writer $_;
              }

              exit;
          }
      } else {
          my $fuzzer_pid = &{$tasks->{fuzz}}($experiment_name, $subject, $version, $context, $waypoints, $binary_context, 0);
          waitpid $fuzzer_pid, 0;
      }
  }
