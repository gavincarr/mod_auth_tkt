#!/usr/bin/env perl
#
# Test guest exclusion
#

use strict;
use warnings FATAL => 'all';

use Apache::Test;
use Apache::TestUtil;
use Apache::TestRequest qw(GET);
use HTTP::Cookies;
use lib "cgi";
use Apache::AuthTkt;

plan tests => 5, need_lwp;

# Turn off automatic redirection following
Apache::TestRequest::user_agent(
  requests_redirectable => 0,
  reset => 1, 
);

ok 1;   # simple load test

my $url = '/secret_noguest/index.cgi';
my $res = GET $url;

# No cookie - should be logged in as guest, but redirected
ok t_cmp($res->code, 307, 'redirected');
ok t_cmp($res->content, qr/redirect.*login/is, 'no ticket: redirect to login');

# Generate ticket and cookie jar
my $at = Apache::AuthTkt->new(conf => 't/conf/extra.conf');
my $ticket = $at->ticket(uid => 'testuser', ip_addr => '127.0.0.1', tokens => 'user');
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
ok t_cmp($res->content, qr/^This is secret_guest, you are testuser/i, 'accepted testuser');


# vim:sw=2:et:sm:smartindent:ft=perl

