#!/usr/bin/env perl
#
# Cookie expiry testing
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

plan tests => 28, need 'LWP', need_apache 2;

ok 1;   # simple load test

my $jar = HTTP::Cookies->new;
my ($url, $res, $cookie, $expires, $calc);

# Reset the TestRequest user_agent to use our cookie jar
Apache::TestRequest::user_agent(
  cookie_jar => $jar,
  requests_redirectable => 0,
  reset => 1, 
);

# Test cookie expiry with no units
$jar->clear;
undef $expires;
$url = '/secret_cookie_expiry1/index.cgi';
$res = GET $url;
ok t_cmp($res->code, 200, 'accepted without valid ticket');
ok t_cmp($res->content, qr/^This is secret_guest, you are guest/i, 'accepted as guest');
print "jar: " . $jar->as_string;
($cookie) = ($jar->as_string =~ m/^(Set-Cookie3: auth_tkt=.*)$/);
($expires) = ($cookie =~ m/expires="?([^;]*?)"?;/) if $cookie;
#print "expires: $expires\n" if $expires;
$calc = DateTime->now(time_zone => 'GMT')->add(days => 1)->strftime('%Y-%m-%d');
#print "calc: $calc\n";
ok t_cmp($expires, qr/^$calc/, 'cookie expires field bare ok');

# Test cookie expiry with seconds (86400s)
$jar->clear;
undef $expires;
$url = '/secret_cookie_expiry2/index.cgi';
$res = GET $url;
ok t_cmp($res->code, 200, 'accepted without valid ticket');
ok t_cmp($res->content, qr/^This is secret_guest, you are guest/i, 'accepted as guest');
#print "jar: " . $jar->as_string;
($cookie) = ($jar->as_string =~ m/^(Set-Cookie3: auth_tkt=.*)$/);
($expires) = ($cookie =~ m/expires="?([^;]*?)"?;/) if $cookie;
#print "expires: $expires\n" if $expires;
$calc = DateTime->now(time_zone => 'GMT')->add(days => 1)->strftime('%Y-%m-%d');
#print "calc: $calc\n";
ok t_cmp($expires, qr/^$calc/, 'cookie expires field seconds ok');

# Test cookie expiry with minutes (120m)
$jar->clear;
$url = '/secret_cookie_expiry3/index.cgi';
$res = GET $url;
ok t_cmp($res->code, 200, 'accepted without valid ticket');
ok t_cmp($res->content, qr/^This is secret_guest, you are guest/i, 'accepted as guest');
#print "jar: " . $jar->as_string;
($cookie) = ($jar->as_string =~ m/^(Set-Cookie3: auth_tkt=.*)$/);
($expires) = ($cookie =~ m/expires="?([^;]*?)"?;/) if $cookie;
#print "expires: $expires\n";
$calc = DateTime->now(time_zone => 'GMT')->add(minutes => 120)->strftime('%Y-%m-%d %H:%M');
print "calc: $calc\n";
ok t_cmp($expires, qr/^$calc/, 'cookie expires field minutes ok');

# Test cookie expiry with hours (3h)
$jar->clear;
$url = '/secret_cookie_expiry4/index.cgi';
$res = GET $url;
ok t_cmp($res->code, 200, 'accepted without valid ticket');
ok t_cmp($res->content, qr/^This is secret_guest, you are guest/i, 'accepted as guest');
#print "jar: " . $jar->as_string;
($cookie) = ($jar->as_string =~ m/^(Set-Cookie3: auth_tkt=.*)$/);
($expires) = ($cookie =~ m/expires="?([^;]*?)"?;/) if $cookie;
#print "expires: $expires\n";
$calc = DateTime->now(time_zone => 'GMT')->add(hours => 3)->strftime('%Y-%m-%d %H');
#print "calc: $calc\n";
ok t_cmp($expires, qr/^$calc/, 'cookie expires field hours ok');

# Test cookie expiry with days (2d)
$jar->clear;
$url = '/secret_cookie_expiry5/index.cgi';
$res = GET $url;
ok t_cmp($res->code, 200, 'accepted without valid ticket');
ok t_cmp($res->content, qr/^This is secret_guest, you are guest/i, 'accepted as guest');
#print "jar: " . $jar->as_string;
($cookie) = ($jar->as_string =~ m/^(Set-Cookie3: auth_tkt=.*)$/);
($expires) = ($cookie =~ m/expires="?([^;]*?)"?;/) if $cookie;
#print "expires: $expires\n";
$calc = DateTime->now(time_zone => 'GMT')->add(days => 2)->strftime('%Y-%m-%d');
#print "calc: $calc\n";
ok t_cmp($expires, qr/^$calc/, 'cookie expires field days ok');

# Test cookie expiry with weeks (3w)
$jar->clear;
$url = '/secret_cookie_expiry6/index.cgi';
$res = GET $url;
ok t_cmp($res->code, 200, 'accepted without valid ticket');
ok t_cmp($res->content, qr/^This is secret_guest, you are guest/i, 'accepted as guest');
#print "jar: " . $jar->as_string;
($cookie) = ($jar->as_string =~ m/^(Set-Cookie3: auth_tkt=.*)$/);
($expires) = ($cookie =~ m/expires="?([^;]*?)"?;/) if $cookie;
#print "expires: $expires\n";
$calc = DateTime->now(time_zone => 'GMT')->add(weeks => 3)->strftime('%Y-%m-%d');
#print "calc: $calc\n";
ok t_cmp($expires, qr/^$calc/, 'cookie expires field weeks ok');

# Test cookie expiry with months (3M)
$jar->clear;
$url = '/secret_cookie_expiry7/index.cgi';
$res = GET $url;
ok t_cmp($res->code, 200, 'accepted without valid ticket');
ok t_cmp($res->content, qr/^This is secret_guest, you are guest/i, 'accepted as guest');
#print "jar: " . $jar->as_string;
($cookie) = ($jar->as_string =~ m/^(Set-Cookie3: auth_tkt=.*)$/);
($expires) = ($cookie =~ m/expires="?([^;]*?)"?;/) if $cookie;
#print "expires: $expires\n";
$calc = DateTime->now(time_zone => 'GMT')->add(days => 90)->strftime('%Y-%m-%d');
#print "calc: $calc\n";
ok t_cmp($expires, qr/^$calc/, 'cookie expires field months ok');

# Test cookie expiry with years (1y)
$jar->clear;
$url = '/secret_cookie_expiry8/index.cgi';
$res = GET $url;
ok t_cmp($res->code, 200, 'accepted without valid ticket');
ok t_cmp($res->content, qr/^This is secret_guest, you are guest/i, 'accepted as guest');
#print "jar: " . $jar->as_string;
($cookie) = ($jar->as_string =~ m/^(Set-Cookie3: auth_tkt=.*)$/);
($expires) = ($cookie =~ m/expires="?([^;]*?)"?;/) if $cookie;
#print "expires: $expires\n";
$calc = DateTime->now(time_zone => 'GMT')->add(days => 365)->strftime('%Y-%m');
#print "calc: $calc\n";
ok t_cmp($expires, qr/^$calc/, 'cookie expires field years ok');

# Test cookie expiry with multiple units (2y 1m 3w 4d)
$jar->clear;
$url = '/secret_cookie_expiry9/index.cgi';
$res = GET $url;
ok t_cmp($res->code, 200, 'accepted without valid ticket');
ok t_cmp($res->content, qr/^This is secret_guest, you are guest/i, 'accepted as guest');
#print "jar: " . $jar->as_string;
($cookie) = ($jar->as_string =~ m/^(Set-Cookie3: auth_tkt=.*)$/);
($expires) = ($cookie =~ m/expires="?([^;]*?)"?;/) if $cookie;
$expires =~ s/\s.*//;
my @expires = split /-/, $expires;
my $expires_dt = DateTime->new(year => $expires[0], month => $expires[1], day => $expires[2]);
printf "expires: %s\n", $expires_dt->strftime("%Y-%m-%d");
$calc = DateTime->now(time_zone => 'GMT')->add(years => 2, months => 1, weeks => 3, days => 4);
printf "calc: %s\n", $calc->strftime("%Y-%m-%d");
my $diff = $expires_dt - $calc;
printf "diff: %s\n", $diff->delta_days;
ok t_cmp(abs $diff->delta_days, qr/^[012]$/, 'cookie expires field years ok (' . $diff->delta_days . ')');
#ok t_cmp($expires, qr/^$calc/, 'cookie expires field years ok');


# vim:sw=2:et:sm:smartindent:ft=perl

