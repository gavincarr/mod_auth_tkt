#!/usr/bin/env perl
print <<EOD
Content-Type: text/plain

This is secret_guest_nocookie2, you are $ENV{REMOTE_USER}.
EOD
