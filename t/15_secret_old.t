#!/usr/bin/env perl
#
# Testing fallback to secret_old
#

use strict;
use warnings FATAL => 'all';

use Apache::Test;
use Apache::TestUtil;
use Apache::TestRequest qw(GET);
use HTTP::Cookies;
use lib "cgi";
use Apache::AuthTkt 2.1;

plan tests => 9, need_lwp;

# Setup cookie jar, turn off automatic redirection following
my $jar = HTTP::Cookies->new;
Apache::TestRequest::user_agent(
  cookie_jar => $jar,
  requests_redirectable => 0,
  reset => 1, 
);

ok 1;   # simple load test

my $at = Apache::AuthTkt->new(conf => 't/conf/extra.conf');
my $url = '/secret_basic/index.html';
my $res;
my $ticket;
my $cookie;

# No ticket - should be redirected
$res = GET $url;
ok t_cmp($res->code, 307, 'redirected');
ok t_cmp($res->content, qr/redirect.*login/is, 'no ticket: redirect to login');

# Generate ticket with current secret - should NOT redirect
$ticket = $at->ticket(uid => 'testuser', ip_addr => '127.0.0.1');
$jar->set_cookie(1, 'auth_tkt', $ticket, '/', '.localdomain');
$res = GET $url;
ok t_cmp($res->code, 200, 'not redirected with ticket');
# Check that the cookie in the response matches our ticket
$jar->extract_cookies($res);
$jar->scan(sub { $cookie = $_[2] if $_[1] eq 'auth_tkt' });
ok t_cmp($ticket, $cookie, "cookie in jar matches ticket i.e. no refresh");

# Generate ticket with old secret - should NOT redirect
$at->secret( $at->secret_old );
$ticket = $at->ticket(uid => 'testuser', ip_addr => '127.0.0.1');
$jar->set_cookie(1, 'auth_tkt', $ticket, '/', '.localdomain');
$res = GET $url;
ok t_cmp($res->code, 200, 'not redirected with ticket');
# Check that the cookie in the response does NOT match our ticket
$jar->extract_cookies($res);
$jar->scan(sub { $cookie = $_[2] if $_[1] eq 'auth_tkt' });
ok ! t_cmp($ticket, $cookie, "cookie in jar does NOT match ticket i.e. cookie has been refreshed");

# Now redo the test with the refreshed $cookie - it should use the current secret, so NOT redirect
$ticket = $cookie;
$res = GET $url;
ok t_cmp($res->code, 200, 'not redirected with ticket');
# Check that the cookie in the response matches our ticket
$jar->extract_cookies($res);
$jar->scan(sub { $cookie = $_[2] if $_[1] eq 'auth_tkt' });
ok t_cmp($ticket, $cookie, "cookie in jar matches ticket i.e. no refresh");

