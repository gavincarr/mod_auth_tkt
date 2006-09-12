#!/usr/bin/env perl
print <<EOD
Content-Type: text/plain

This is secret_guest, you are $ENV{REMOTE_USER}.
EOD
