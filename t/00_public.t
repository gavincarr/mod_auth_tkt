#!/usr/bin/env perl

use strict;
use warnings FATAL => 'all';

use Apache::Test;
use Apache::TestUtil;
use Apache::TestRequest 'GET_BODY';

plan tests => 2;

ok 1;   # simple load test

my $url = '/public.html';
my $data = GET_BODY $url;

ok t_cmp($data, qr/^This is public/, 'GET on public file');

# vim:sw=2:et:sm:smartindent:ft=perl

