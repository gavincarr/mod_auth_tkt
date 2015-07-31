#!/usr/bin/env perl
#
# Test auth ticket timeouts (TKTAuthTimeoutMin set to 1)
#

use strict;
use warnings FATAL => 'all';

use Apache::Test;
use Apache::TestUtil;
use Apache::TestRequest qw(GET);
use HTTP::Cookies;
use lib "cgi";
use Apache::AuthTkt;
use File::Basename;

plan tests => 9, need 'LWP', { "env variable MAT_TEST_TIMEOUTS not set" => $ENV{MAT_TEST_TIMEOUTS} };

# Turn off automatic redirection following
Apache::TestRequest::user_agent(
  reset => 1,
  requests_redirectable => 0,
);

ok 1;   # simple load test

my $url = '/secret_timeout_refresh/index.html';
my $res = GET $url;

# No cookie - should be redirected
ok t_cmp($res->code, 307, 'redirected');
ok t_cmp($res->content, qr/redirect.*login/is, 'no ticket: redirect to login');

# Generate ticket and cookie jar
my $at = Apache::AuthTkt->new(conf => 't/conf/extra.conf');
my $ticket = $at->ticket(uid => 'testuser', ip_addr => '127.0.0.1');
my $jar = HTTP::Cookies->new;
$jar->set_cookie(1, 'auth_tkt', $ticket, '/', '.localdomain');

# Reset the TestRequest user_agent to use our cookie jar
Apache::TestRequest::user_agent(
  reset => 1,
  cookie_jar => $jar,
  requests_redirectable => 0,
);

# Helper subs
sub nap {
  my ($t) = @_;
  print "(sleeping for $t seconds ...)\n";
  sleep $t;
}

# Retest with our cookie - should NOT redirect
$res = GET $url;
ok t_cmp($res->code, 200, 'not redirected with ticket take 1');

# Sleep for 20 seconds and retry (timeout is 1 minute) - should be accepted
nap 20;
$res = GET $url;
ok t_cmp($res->code, 200, 'not redirected with ticket take 2');

# Sleep for another 20 seconds and retry (timeout is 1 minute) - should be accepted
nap 20;
$res = GET $url;
ok t_cmp($res->code, 200, 'not redirected with ticket take 3');

# Sleep for another 25 seconds and retry (timeout is 1 minute) - should also be
#   okay, because the ticket will have been refreshed
nap 25;
$res = GET $url;
ok t_cmp($res->code, 200, 'not redirected with ticket take 4');

# Finally sleep for a full 65 seconds, which should force the timeout
nap 65;
$res = GET $url;
ok t_cmp($res->code, 307);
ok t_cmp($res->content, qr/redirect.*timeout\.cgi/is, 'take 5: redirect to timeout.cgi');


# vim:sw=2:et:sm:smartindent:ft=perl

