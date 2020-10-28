#!/usr/bin/perl

use strict;
use warnings;
use POSIX qw(mkfifo);

  my $NAMED_PIPE_PATH = "/tmp/vvdump";

  if (! -e $NAMED_PIPE_PATH) {
      mkfifo($NAMED_PIPE_PATH, 0700) or die "Could not create named pipe at $NAMED_PIPE_PATH: $!";
  }

  # pipe opened in rw mode so that it remains open even after we have read stuff
  my $named_pipe_fh;
  open $named_pipe_fh, "+<", $NAMED_PIPE_PATH or die "Could not open named pipe at $NAMED_PIPE_PATH: $!";

  print "Opened named pipe at $NAMED_PIPE_PATH. Waiting for data...\n";
  while (<$named_pipe_fh>) {
      $_ =~ s/\000//;
      print "Received: $_";
  }

  close $named_pipe_fh;
  exit(0);
