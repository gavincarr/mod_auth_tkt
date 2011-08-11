#!/usr/bin/env perl
#
# Virtual host mod_auth_tkt testing, global secret
#

use strict;
use warnings FATAL => 'all';

use Apache::Test;
use Apache::TestUtil;
use Apache::TestRequest qw(GET);
use HTTP::Cookies;
use lib "cgi";
use Apache::AuthTkt;

plan tests => 7, need_lwp;

# Setup cookie jar, turn off automatic redirection following
my $jar = HTTP::Cookies->new;
Apache::TestRequest::user_agent(
  cookie_jar => $jar,
  requests_redirectable => 0,
  reset => 1, 
);

ok 1;   # simple load test

# Figure out host/port for vhost
my $vhost = 'VHostGlobalSecret';
my $config = Apache::Test::config();
Apache::TestRequest::module($vhost);
my $hostport = Apache::TestRequest::hostport($config);

my $url = "http://$hostport/index.html";
my $at = Apache::AuthTkt->new(conf => 't/conf/extra.conf');
my $res = GET $url;
my $ticket;

# No cookie - should be redirected
ok t_cmp($res->code, 307, 'redirected');
ok t_cmp($res->content, qr/redirect.*login/is, 'no ticket: redirect to login');

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

# Retest with bad ip address - should redirect
$ticket = $at->ticket(uid => 'testuser', ip_addr => '192.168.0.1');
$jar->set_cookie(1, 'auth_tkt', $ticket, '/', '.localdomain');
$res = GET $url;
ok t_cmp($res->code, 307, 'redirect with incorrect IP address');

# vim:sw=2:et:sm:smartindent:ft=perl

