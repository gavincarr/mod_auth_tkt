#!/usr/bin/env perl
#
# Test the Perl Apache::AuthTkt digest handling,
# verifying it works like the C module.
#

use strict;
use warnings FATAL => 'all';

use Apache::Test;
use Apache::TestUtil;

use lib "cgi";
use Apache::AuthTkt;

# use mixed case to verify normalization
my @digest_types = qw( Md5 sha256 SHa512 );

plan tests => scalar(@digest_types);

my $ip = '127.0.0.1';

for my $digest_type (@digest_types) {
    my $at = Apache::AuthTkt->new( conf => 't/conf/extra.conf', digest_type => $digest_type );
    my $ticket = $at->ticket( uid => 'testuser', ip_addr => $ip );
    ok $at->validate_ticket( $ticket, ip_addr => $ip );
}
