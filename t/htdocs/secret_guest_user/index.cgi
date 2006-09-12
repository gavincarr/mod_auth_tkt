#!/usr/bin/env perl
print <<EOD
Content-Type: text/plain

This is secret_guest_user, you are $ENV{REMOTE_USER}.
EOD
