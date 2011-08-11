#!/usr/bin/env perl
#
# Testing TKTAuthCookieSecure flag
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

plan tests => 8, need_lwp;

ok 1;   # simple load test

my $jar = HTTP::Cookies->new;
my ($url, $res, $cookie);

# Reset the TestRequest user_agent to use our cookie jar
Apache::TestRequest::user_agent(
  cookie_jar => $jar,
  requests_redirectable => 0,
  reset => 1, 
);

# Test TKTAuthCookieSecure on
$jar->clear;
undef $cookie;
$url = '/secret_cookie_secure1/index.cgi';
$res = GET $url;
ok t_cmp($res->code, 200, 'accepted without valid ticket');
ok t_cmp($res->content, qr/^This is secret_guest, you are guest/i, 'accepted as guest');
#print "jar: " . $jar->as_string . "\n";
($cookie) = ($jar->as_string =~ m/^(Set-Cookie3: auth_tkt=.*)$/);
#print "cookie: $cookie\n";
ok t_cmp($cookie, qr/; secure;/, 'secure flag found');

# Test TKTAuthCookieSecure off
$jar->clear;
undef $cookie;
$url = '/secret_cookie_secure2/index.cgi';
$res = GET $url;
ok t_cmp($res->code, 200, 'accepted without valid ticket');
ok t_cmp($res->content, qr/^This is secret_guest, you are guest/i, 'accepted as guest');
#print "jar: " . $jar->as_string . "\n";
($cookie) = ($jar->as_string =~ m/^(Set-Cookie3: auth_tkt=.*)$/);
#print "cookie: $cookie\n";
ok t_cmp($cookie, qr/auth_tkt=/, 'cookie found');
ok ! t_cmp($cookie, qr/; secure;/, 'no secure flag found');


# vim:sw=2:et:sm:smartindent:ft=perl

