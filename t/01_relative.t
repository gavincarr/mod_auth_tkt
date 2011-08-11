#!/usr/bin/env perl
#
# Basic mod_auth_tkt testing, with minimal config
#

use strict;
use warnings FATAL => 'all';

use Apache::Test;
use Apache::TestUtil;
use Apache::TestRequest qw(GET);
use HTTP::Cookies;
use lib "cgi";
use Apache::AuthTkt;

plan tests => 10, need_lwp;

# Setup cookie jar, turn off automatic redirection following
my $jar = HTTP::Cookies->new;
Apache::TestRequest::user_agent(
  cookie_jar => $jar,
  requests_redirectable => 0,
  reset => 1, 
);

ok 1;   # simple load test

my $at = Apache::AuthTkt->new(conf => 't/conf/extra.conf');
my $url = '/secret_relative_url/index.html';
my $res = GET $url;
my $ticket;

# No cookie - should be redirected
ok t_cmp($res->code, 307, 'redirected');
ok t_cmp($res->content, qr/redirect.*login/is, 'no ticket: redirect to login');
ok t_cmp($res->header('Location'), qr!^http://localhost.localdomain//pub/login.cgi!, 'redirect is to absolute url');

# Generate good ticket - should NOT redirect
$ticket = $at->ticket(uid => 'testuser', ip_addr => '127.0.0.1');
$jar->set_cookie(1, 'auth_tkt', $ticket, '/', '.localdomain');
$res = GET $url;
ok t_cmp($res->code, 200, 'not redirected with ticket');

# Retry with non-base64-escaped ticket - should NOT redirect
$ticket = $at->ticket(uid => 'testuser', ip_addr => '127.0.0.1', base64 => 0);
$jar->set_cookie(1, 'auth_tkt', $ticket, '/', '.localdomain');
$res = GET $url;
ok t_cmp($res->code, 200, 'not redirected with non-base64 ticket');

# Retest with munged ticket - should redirect
$ticket =~ s/^../XX/;
$jar->set_cookie(1, 'auth_tkt', $ticket, '/', '.localdomain');
$res = GET $url;
ok t_cmp($res->code, 307, 'redirect with munged cookie');
ok t_cmp($res->header('Location'), qr!^http://localhost.localdomain//pub/login.cgi!, 'redirect is to absolute url');

# Retest with bad ip address - should redirect
$ticket = $at->ticket(uid => 'testuser', ip_addr => '192.168.0.1');
$jar->set_cookie(1, 'auth_tkt', $ticket, '/', '.localdomain');
$res = GET $url;
ok t_cmp($res->code, 307, 'redirect with incorrect IP address');
ok t_cmp($res->header('Location'), qr!^http://localhost.localdomain//pub/login.cgi!, 'redirect is to absolute url');

# vim:sw=2:et:sm:smartindent:ft=perl

