#!/usr/bin/env perl
#
# Back argument testing
#

use strict;
use warnings FATAL => 'all';

use Apache::Test;
use Apache::TestUtil;
use Apache::TestRequest qw(GET);
use HTTP::Cookies;
use lib "cgi";
use Apache::AuthTkt 2.1;

plan tests => 7, need_lwp;

# Setup cookie jar, turn off automatic redirection following
my $jar = HTTP::Cookies->new;
Apache::TestRequest::user_agent(
  cookie_jar => $jar,
  requests_redirectable => 0,
  reset => 1,
);

ok 1;   # simple load test

my $at = Apache::AuthTkt->new(conf => 't/conf/extra.conf');
my $url;
my $res;

# Default config - should be redirected with standard back argument
$url = '/secret_basic/index.html';
$res = GET $url;
ok t_cmp($res->code, 307, 'redirected');
ok t_cmp($res->content, qr/redirect.*\?back=http/is, 'redirect, default back argument set');

# Explicit back arg - should be redirected with non-standard back argument
$url = '/secret_back_explicit/';
$res = GET $url;
ok t_cmp($res->code, 307, 'redirected');
ok t_cmp($res->content, qr/redirect.*\?redirect_to=http/is, 'redirect, non-standard back argument set');

# Null back arg - should be redirected without any back argument
$url = '/secret_back_none/';
$res = GET $url;
ok t_cmp($res->code, 307, 'redirected');
ok t_cmp($res->content, qr/redirect.*login\.cgi"/is, 'redirect, NO back argument set');

# vim:sw=2:et:sm:smartindent:ft=perl

