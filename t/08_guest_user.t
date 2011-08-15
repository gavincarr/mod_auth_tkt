#!/usr/bin/env perl
#
# Guest user testing
#

use strict;
use warnings FATAL => 'all';

use Apache::Test;
use Apache::TestUtil;
use Apache::TestRequest qw(GET);
use HTTP::Cookies;
use lib "cgi";
use Apache::AuthTkt;
use DateTime;

plan tests => 22, need_lwp;

# Turn off automatic redirection following
Apache::TestRequest::user_agent(
  requests_redirectable => 0,
  reset => 1, 
);

ok 1;   # simple load test

my $url = '/secret_guest_user/index.cgi';
my $res = GET $url;

# Generate ticket and cookie jar
my $at = Apache::AuthTkt->new(conf => 't/conf/extra.conf');
my $ticket = $at->ticket(uid => 'testuser', ip_addr => '127.0.0.1');
my $jar = HTTP::Cookies->new;
$jar->set_cookie(1, 'auth_tkt', $ticket, '/', '.localdomain');
# print $jar->as_string;

# Reset the TestRequest user_agent to use our cookie jar
Apache::TestRequest::user_agent(
  cookie_jar => $jar,
  requests_redirectable => 0,
  reset => 1, 
);

# Retest with valid cookie - should NOT redirect
$res = GET $url;
ok t_cmp($res->code, 200, 'accepted with valid ticket');
ok t_cmp($res->content, qr/^This is secret_guest_user, you are testuser/i, 'accepted testuser');

# Test with no cookie - should accept as guest login
$jar->clear;
$res = GET $url;
ok t_cmp($res->code, 200, 'accepted without valid ticket');
ok t_cmp($res->content, qr/^This is secret_guest_user, you are aguestbyanyothername/i, 'accepted as TKTAuthGuestUser');

# Simple cookie expiry test
my ($cookie) = ($jar->as_string =~ m/^(Set-Cookie3: auth_tkt=.*)$/);
my ($expires) = ($cookie =~ m/expires="?([^;]*?)"?;/) if $cookie;
# print "$expires\n";
my $tomorrow = DateTime->now(time_zone => 'GMT')->add(days => 1)->strftime('%Y-%m-%d');
# print "$tomorrow\n";
if (have_apache 2) {
  ok t_cmp($expires, qr/^$tomorrow/, 'cookie expires field set to tomorrow');
} else {
  ok t_cmp($expires, undef, 'cookie expires field not set on apache 1');
}

# UUID tests - simple %U UUID
$url = '/secret_guest_user_uuid1/index.cgi';
$jar->clear;
$res = GET $url;
ok t_cmp($res->code, 200, 'accepted without valid ticket');
if (have_apache 2) {
  ok t_cmp($res->content, qr/^This is secret_guest_user_uuid, you are guest-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.$/, 'accepted as UUIDed TKTAuthGuestUser');
} else {
  ok t_cmp($res->content, qr/^This is secret_guest_user_uuid, you are guest-%U/, 'accepted as guest-%U (uuid unsupported on apache 1.3.x)');
}

# Check partial match
$url = '/secret_guest_user_uuid2/index.cgi';
$jar->clear;
$res = GET $url;
ok t_cmp($res->code, 200, 'accepted without valid ticket');
ok t_cmp($res->content, qr/^This is secret_guest_user_uuid, you are guest-12U/, 
  'partial match ignored');

# Standard size-limited UUID (%12U)
$url = '/secret_guest_user_uuid3/index.cgi';
$jar->clear;
$res = GET $url;
ok t_cmp($res->code, 200, 'accepted without valid ticket');
if (have_apache 2) {
  ok t_cmp($res->content, qr/^This is secret_guest_user_uuid, you are guest-[0-9a-f]{8}-[0-9a-f]{3}\.$/, 'size limited UUID (%12U) ok');
} else {
  ok t_cmp($res->content, qr/^This is secret_guest_user_uuid, you are guest-%12U/, 'accepted as guest-%12U (uuid unsupported on apache 1.3.x)');
}

# Edge conditions with size-limited UUIDs (%0U, %1U)
$url = '/secret_guest_user_uuid4/index.cgi';
$jar->clear;
$res = GET $url;
ok t_cmp($res->code, 200, 'accepted without valid ticket');
if (have_apache 2) {
  ok t_cmp($res->content, qr/^This is secret_guest_user_uuid, you are guest-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.$/, 'zero size limited UUID (%0U) treated as %U');
} else {
  ok t_cmp($res->content, qr/^This is secret_guest_user_uuid, you are guest-%0U/, 'accepted as guest-%0U (uuid unsupported on apache 1.3.x)');
}

$url = '/secret_guest_user_uuid5/index.cgi';
$jar->clear;
$res = GET $url;
ok t_cmp($res->code, 200, 'accepted without valid ticket');
if (have_apache 2) {
  ok t_cmp($res->content, qr/^This is secret_guest_user_uuid, you are guest-[0-9a-f]\.$/, '%1U size-limited UUID ok');
} else {
  ok t_cmp($res->content, qr/^This is secret_guest_user_uuid, you are guest-%1U/, 'accepted as guest-%1U (uuid unsupported on apache 1.3.x)');
}

# Various size-limited UUIDs (%24U, %36U, %50U)
$url = '/secret_guest_user_uuid6/index.cgi';
$jar->clear;
$res = GET $url;
ok t_cmp($res->code, 200, 'accepted without valid ticket');
if (have_apache 2) {
  ok t_cmp($res->content, qr/^This is secret_guest_user_uuid, you are guest-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-\.$/, '%24U size-limited UUID ok');
} else {
  ok t_cmp($res->content, qr/^This is secret_guest_user_uuid, you are guest-%24U/, 'accepted as guest-%24U (uuid unsupported on apache 1.3.x)');
}

$url = '/secret_guest_user_uuid7/index.cgi';
$jar->clear;
$res = GET $url;
ok t_cmp($res->code, 200, 'accepted without valid ticket');
if (have_apache 2) {
  ok t_cmp($res->content, qr/^This is secret_guest_user_uuid, you are guest-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.$/, '%36U size-limited UUID ok');
} else {
  ok t_cmp($res->content, qr/^This is secret_guest_user_uuid, you are guest-%36U/, 'accepted as guest-%36U (uuid unsupported on apache 1.3.x)');
}

$url = '/secret_guest_user_uuid8/index.cgi';
$jar->clear;
$res = GET $url;
ok t_cmp($res->code, 200, 'accepted without valid ticket');
if (have_apache 2) {
  ok t_cmp($res->content, qr/^This is secret_guest_user_uuid, you are guest-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.$/, '%50U size-limited UUID truncated to %U');
} else {
  ok t_cmp($res->content, qr/^This is secret_guest_user_uuid, you are guest-%50U/, 'accepted as guest-%50U (uuid unsupported on apache 1.3.x)');
}


# vim:sw=2:et:sm:smartindent:ft=perl

