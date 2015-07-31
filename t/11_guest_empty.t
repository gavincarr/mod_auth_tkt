#!/usr/bin/env perl
#
# Guest login testing
#

use strict;
use warnings FATAL => 'all';

use Apache::Test;
use Apache::TestUtil;
use Apache::TestRequest qw(GET);
use HTTP::Cookies;
use lib "cgi";
use Apache::AuthTkt;

plan tests => 6, need_lwp;

# Turn off automatic redirection following
Apache::TestRequest::user_agent(
  requests_redirectable => 0,
  reset => 1,
);

ok 1;   # simple load test

my $url = '/secret_guest_empty/index.cgi';
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
ok t_cmp($res->content, qr/^This is secret_guest_empty, you are testuser\./i, 'accepted testuser');

# Test with no cookie - should accept as guest login, but username should be ''
# and not set a cookie
$jar->clear;
$res = GET $url;
ok t_cmp($res->code, 200, 'accepted without valid ticket');
ok t_cmp($res->content, qr/^This is secret_guest_empty, you are \./i, 'accepted as empty guest');
ok t_cmp($jar->as_string, '', 'NO auth_tkt cookie set');

# vim:sw=2:et:sm:smartindent:ft=perl

