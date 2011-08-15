#!/usr/bin/env perl
#
# Test various bad ticket formats
#

use strict;
use warnings FATAL => 'all';

use Apache::Test;
use Apache::TestUtil;
use Apache::TestRequest qw(GET);
use HTTP::Cookies;
use lib "cgi";
use Apache::AuthTkt;

plan tests => 8, need_lwp;

# Turn off automatic redirection following
Apache::TestRequest::user_agent(
  requests_redirectable => 0,
  reset => 1, 
);

ok 1;   # simple load test

my $url = '/secret_basic/index.html';
my $res = GET $url;

# Test no cookie - should be redirected
ok t_cmp($res->code, 307, 'redirected');
ok t_cmp($res->content, qr/redirect.*login/is, 'no ticket: redirect to login');

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

# Test good ticket - should NOT redirect
$res = GET $url;
ok t_cmp($res->code, 200, 'not redirected with good ticket');

# Test with empty ticket
$jar->set_cookie(1, 'auth_tkt', '', '/', '.localdomain');
$res = GET $url;
ok t_cmp($res->code, 307, 'redirect with empty ticket');

# Test very small ticket I
$jar->set_cookie(1, 'auth_tkt', 'X', '/', '.localdomain');
$res = GET $url;
ok t_cmp($res->code, 307, 'redirect with very small ticket I');

# Test very small ticket II
$jar->set_cookie(1, 'auth_tkt', 'ABC', '/', '.localdomain');
$res = GET $url;
ok t_cmp($res->code, 307, 'redirect with very small ticket II');

# Test very large ticket
$jar->set_cookie(1, 'auth_tkt', 'X' x 1025, '/', '.localdomain');
$res = GET $url;
ok t_cmp($res->code, 307, 'redirect with very large ticket');

# vim:sw=2:et:sm:smartindent:ft=perl

