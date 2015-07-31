#!/usr/bin/env perl
print <<EOD
Content-Type: text/plain

This is secret_guest_empty, you are $ENV{REMOTE_USER}.
EOD
