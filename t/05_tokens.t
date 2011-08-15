#!/usr/bin/env perl
#
# Token testing
#

use strict;
use warnings FATAL => 'all';

use Apache::Test;
use Apache::TestUtil;
use Apache::TestRequest qw(GET);
use HTTP::Cookies;
use lib "cgi";
use Apache::AuthTkt;

plan tests => 13, need_lwp;

# Turn off automatic redirection following
Apache::TestRequest::user_agent(
  requests_redirectable => 0,
  reset => 1, 
);

ok 1;   # simple load test

# URL requires 'finance' or 'admin' tokens
my $url = '/secret_tokens/index.html';
my $res = GET $url;

# No cookie - should be redirected
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

# Retest with valid but tokenless cookie - should redirect
$res = GET $url;
ok t_cmp($res->code, 307, 'redirected');
ok t_cmp($res->content, qr/redirect.*login/is, 'no tokens: redirect to login');

# Test valid token
$ticket = $at->ticket(uid => 'testuser', ip_addr => '127.0.0.1',
  tokens => 'finance');
$jar->set_cookie(1, 'auth_tkt', $ticket, '/', '.localdomain');
$res = GET $url;
ok t_cmp($res->code, 200, 'accepted with single token');
ok t_cmp($res->content, qr/^This is secret_tokens/i, 'content ok');

# Test valid token in list
$ticket = $at->ticket(uid => 'testuser', ip_addr => '127.0.0.1',
  tokens => 'audit,management,finance');
$jar->set_cookie(1, 'auth_tkt', $ticket, '/', '.localdomain');
$res = GET $url;
ok t_cmp($res->code, 200, 'accepted with valid token in list');

# Test multiple valid tokens in list
$ticket = $at->ticket(uid => 'testuser', ip_addr => '127.0.0.1',
  tokens => 'audit, management, finance, admin');
$jar->set_cookie(1, 'auth_tkt', $ticket, '/', '.localdomain');
$res = GET $url;
ok t_cmp($res->code, 200, 'accepted with multiple valid tokens');

# Test no valid tokens in list - should be redirected
$ticket = $at->ticket(uid => 'testuser', ip_addr => '127.0.0.1',
  tokens => 'audit,management');
$jar->set_cookie(1, 'auth_tkt', $ticket, '/', '.localdomain');
$res = GET $url;
ok t_cmp($res->code, 307, 'redirected with no valid tokens');
ok t_cmp($res->content, qr/redirect.*login/is, 'no valid tokens: redirect to login');

# Test long token - should be redirected
$ticket = $at->ticket(uid => 'testuser', ip_addr => '127.0.0.1',
  tokens => 'financevil');
$jar->set_cookie(1, 'auth_tkt', $ticket, '/', '.localdomain');
$res = GET $url;
ok t_cmp($res->code, 307, 'redirected with long token');
ok t_cmp($res->content, qr/redirect.*login/is, 'long token: redirect to login');


# vim:sw=2:et:sm:smartindent:ft=perl

