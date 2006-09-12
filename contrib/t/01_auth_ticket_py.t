#!/usr/bin/perl
#
# Test auth_ticket.py against Apache::AuthTicket
#

use strict;
use warnings FATAL => 'all';
use Test::More tests => 2;
use File::Basename;
BEGIN {
  use lib dirname($0) . "/../cgi";
}
use Apache::AuthTicket;

my $secret = 'cb3e1d39-98eb-4161-8bbd-f4e706999b0e';
my $ts = 1108811260;
my $username = 'foobar';
my $ip = '192.168.1.1';

my ($at, $ticket1, $ticket2, $cookie1, $cookie2);

# Get Apache::AuthTicket versions
$at = Apache::AuthTicket->new(secret => $secret);
$ticket1 = $at->ticket(uid => $username, ip_addr => $ip, ts => $ts, base64 => 0);
$cookie1 = $at->cookie(uid => $username, ip_addr => $ip, ts => $ts);
$cookie1 =~ s/^.*auth_tkt="?//;  # Normalise       "
$cookie1 =~ s/"?;.*//;           # Normalise       "

# Get auth_ticket.py versions
$ticket2 = qx(python -c "import auth_ticket; atp = auth_ticket.AuthTicket('$secret', '$username', '$ip', time=$ts); print atp.cookie_value()");
chomp $ticket2;
$cookie2 = qx(python -c "import auth_ticket; atp = auth_ticket.AuthTicket('$secret', '$username', '$ip', time=$ts); print atp.cookie()");
chomp $cookie2;
$cookie2 =~ s/^.*auth_tkt="?//;  # Normalise       "
$cookie2 =~ s/"?;.*//;           # Normalise       "

# Test
is($ticket1, $ticket2, 'ticket test 1');
is($cookie1, $cookie2, 'cookie test 1');

# arch-tag: f32271e6-6fac-4496-bcbd-96f1dea98f34
# vim:sw=2:et:sm:smartindent

