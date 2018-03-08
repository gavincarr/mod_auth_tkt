#!/usr/bin/env perl

use strict;
use warnings FATAL => 'all';

use Apache::Test;
use Apache::TestUtil;

use lib "cgi";
use Apache::AuthTkt;

# use mixed case to verify normalization
my @digest_types = qw( Md5 sha256 SHa512 );

plan tests => scalar(@digest_types);

for my $digest_type (@digest_types) {
    my $at = Apache::AuthTkt->new( conf => 't/conf/extra.conf' );
    my $ticket = $at->ticket( uid => 'testuser', ip_addr => '127.0.0.1' );
    ok $at->validate_ticket($ticket);
}
