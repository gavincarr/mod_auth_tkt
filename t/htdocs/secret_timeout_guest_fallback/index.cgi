#!/usr/bin/env perl
print <<EOD
Content-Type: text/plain

This is secret_timeout_guest_fallback, you are $ENV{REMOTE_USER}.
EOD
