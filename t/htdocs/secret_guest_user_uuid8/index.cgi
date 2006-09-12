#!/usr/bin/env perl
print <<EOD
Content-Type: text/plain

This is secret_guest_user_uuid, you are $ENV{REMOTE_USER}.
EOD
