#
# Module to generate authentication tickets for mod_auth_tkt apache module.
#

package Apache::AuthTkt;

use 5.005;
use Carp;
use Digest::MD5 qw(md5_hex);
use MIME::Base64;
use strict;
use vars qw($VERSION $AUTOLOAD);

$VERSION = '0.07';

my $me = 'Apache::AuthTkt';
my $PREFIX = 'TKTAuth';
my %DEFAULTS = (
    TKTAuthCookieName           => 'auth_tkt',
    TKTAuthBackArgName          => 'back',
    TKTAuthTimeout              => 2 * 60 * 60,
    TKTAuthTimeoutMin           => 2 * 60,
    TKTAuthTimeoutRefresh       => 0.5,
    TKTAuthGuestLogin           => 0,
    TKTAuthGuestUser            => 'guest',
    TKTAuthIgnoreIP             => 0,
    TKTAuthRequireSSL           => 0,
    TKTAuthCookieSecure         => 0,
);
my %BOOLEAN = map { $_ => 1 } qw(
    TKTAuthGuestLogin TKTAuthIgnoreIP TKTAuthRequireSSL TKTAuthCookieSecure
);
# Default TKTAuthDomain to host part of HTTP_HOST, or SERVER_NAME
($DEFAULTS{TKTAuthDomain}) = split /:/, $ENV{HTTP_HOST} || '';
$DEFAULTS{TKTAuthDomain} ||= $ENV{SERVER_NAME};
my %ATTR = map { $_ => 1 } qw(
    conf secret 
    cookie_name back_cookie_name back_arg_name domain cookie_expires
    login_url timeout_url post_timeout_url unauth_url 
    timeout timeout_min timeout_refresh token 
    guest_login guest_user ignore_ip require_ssl cookie_secure
);
#my %TICKET_ARGS = map { $_ => 1 } 

# Helper routine to convert time units into seconds
my %units = (
  s => 1,
  m => 60,
  h => 3600,
  d => 86400,
  w => 7 * 86400,
  M => 30 * 86400,
  y => 365 * 86400,
);
sub convert_time_seconds
{
    my $self = shift;
    local $_ = shift;
    return $1 if m/^\s*(\d+)\s*$/;
    my $sec = 0;
    while (m/\G(\d+)([shdwmMy])\b\s*/gc) {
        my $amt = $1;
        my $unit = $2 || 's';
        $sec += $amt * $units{$unit};
#       print STDERR "$amt : $unit : $sec\n";
    }
    return $sec;
}

# Parse (simplistically) the given apache config file for TKTAuth directives
sub parse_conf
{
    my $self = shift;
    my ($conf) = @_;

    my %seen = ();
    open CF, "<$conf" or
        die "[$me] open of config file '$conf' failed: $!";

    # Take settings from first instance of each TKTAuth directive found
    local $/ = "\n";
    while (<CF>) {
        if (m/^\s*(${PREFIX}\w+)\s+(.*)/) {
            $seen{$1} = $2 unless exists $seen{$1};
        }
    }

    close CF;
    die "[$me] TKTAuthSecret directive not found in config file '$conf'"
        unless $seen{TKTAuthSecret};

    # Set directives as $self attributes
    my %merge = ( %DEFAULTS, %seen );
    for my $directive (keys %merge) {
        local $_ = $directive;
        s/^TKTAuth(\w)/\L$1/;
        s/([a-z])([A-Z]+)/\L$1_$2/g;
        $merge{$directive} =~ s/^"([^"]+)"$/$1/ if $merge{$directive};
        if ($BOOLEAN{$directive}) {
            $merge{$directive} = 0 
                if $merge{$directive} =~ m/^(off|no|false)$/i;
            $merge{$directive} = 1 
                if $merge{$directive} =~ m/^(on|yes|true)$/i;
        }
        elsif (defined $merge{$directive}) {
            $merge{$directive} =~ s/^\s+//;
            $merge{$directive} =~ s/\s+$//;
        }
        if ($directive eq 'TKTAuthCookieExpires' || $directive eq 'TKTAuthTimeout') {
          $self->{$_} = $self->convert_time_seconds($merge{$directive});
        }
        else {
          $self->{$_} = $merge{$directive};
        }
    }
}

# Process constructor args
sub init
{
    my $self = shift;
    my %arg = @_;

    # Check for invalid args
    for (keys %arg) {
        croak "[$me] invalid argument to constructor: $_" unless exists $ATTR{$_};
    }

    # Parse config file if set
    if ($arg{conf}) {
        $self->parse_conf($arg{conf});
    }

    # Store/override from given args
    $self->{$_} = $arg{$_} foreach keys %arg;

    croak "[$me] bad constructor - 'secret' or 'conf' argument required"
        unless $self->{conf} || $self->{secret};

    $self;
}

# Constructor
sub new
{
    my $class = shift;
    my $self = {};
    bless $self, $class;
    $self->init(@_);
}

# Setup autoload accessors/mutators
sub AUTOLOAD {
    my $self = shift;
    my $attr = $AUTOLOAD;
    $attr =~ s/.*:://;
    die qq(Can't locate object method "$attr" via package "$self")
        unless $ATTR{$attr};
    @_ and $self->{$attr} = $_[0];
    return $self->{$attr};
}

sub DESTROY {}

sub errstr
{
    my $self = shift;
    $@[0] and $self->{errstr} = join ' ', @_;
    $self->{errstr};
}

# Return a mod_auth_tkt ticket containing the given user details
sub ticket
{
    my $self = shift;
    my %DEFAULTS = (
        base64 => 1,
        data => '',
        tokens => '',
    );
    my %arg = ( %DEFAULTS, %$self, @_ );
    $arg{uid} = $self->guest_user unless exists $arg{uid};
    $arg{ip_addr} = $arg{ignore_ip} ? '0.0.0.0' : $ENV{REMOTE_ADDR}
        unless exists $arg{ip_addr};
    # 0 or undef ip_addr treated as 0.0.0.0
    $arg{ip_addr} ||= '0.0.0.0';

    # Data cleanups
    if ($arg{tokens}) {
        $arg{tokens} =~ s/\s+,/,/g;
        $arg{tokens} =~ s/,\s+/,/g;
    }

    # Data checks
    if ($arg{ip_addr} !~ m/^([12]?[0-9]?[0-9]\.){3}[12]?[0-9]?[0-9]$/) {
        $self->errstr("invalid ip_addr '$arg{ip_addr}'");
        return undef;
    }
    if ($arg{tokens} =~ m/[!@#\$%^&*\];\s]/) {
        $self->errstr("invalid chars in tokens '$arg{tokens}'");
        return undef;
    }

    # Calculate the hash for the ticket
    my $ts = $arg{ts} || time;
    my @ip = split /\./, $arg{ip_addr};
    my @ts = ( (($ts & 0xff000000) >> 24),
               (($ts & 0xff0000) >> 16),
               (($ts & 0xff00) >> 8),
               (($ts & 0xff)) );
    my $ipts = pack("C8", @ip, @ts);
    my $raw = $ipts . $self->secret . $arg{uid} . "\0" . $arg{tokens} . "\0" . $arg{data};
    my $digest0 = md5_hex($raw);
    my $digest = md5_hex($digest0 . $self->secret);

    if ($arg{debug}) {
        print STDERR "ts: $ts\nip_addr: $arg{ip_addr}\nuid: $arg{uid}\ntokens: $arg{tokens}\ndata: $arg{data}\n";
        print STDERR "secret: " . $self->secret . "\n";
        print STDERR "raw: '$raw'\n";
        my $len = length($raw);
        print STDERR "digest0: $digest0 (input length $len)\n";
        print STDERR "digest: $digest\n";
    }

    # Construct the ticket itself
    my $ticket = sprintf "%s%08x%s!", $digest, $ts, $arg{uid};
    $ticket .= $arg{tokens} . '!' if $arg{tokens};
    $ticket .= $arg{data};
    
    return $arg{base64} ? encode_base64($ticket, '') : $ticket;
}

# Return a cookie containing a mod_auth_tkt ticket 
sub cookie
{
    my $self = shift;
    my %DEFAULTS = (
        cookie_name => 'auth_tkt',
        cookie_path => '/',
    );
    my %arg = ( %DEFAULTS, %$self, @_ );
    $arg{cookie_domain} ||= $self->domain;

    # Get ticket, forcing base64 for cookies
    my $ticket = $self->ticket(@_, base64 => 1) or return;

    my $cookie_fmt = "%s=%s%s%s%s";
    my $path_elt = "; path=$arg{cookie_path}";
    my $domain_elt = $arg{cookie_domain} ? "; domain=$arg{cookie_domain}" : '';
    my $secure_elt = $arg{cookie_secure} ? "; secure" : '';
    return sprintf $cookie_fmt, 
           $arg{cookie_name}, $ticket, $domain_elt, $path_elt, $secure_elt;
}


1;

__END__

=head1 NAME

Apache::AuthTkt - module to generate authentication tickets for 
mod_auth_tkt apache module.


=head1 SYNOPSIS

    # Constructor - either (preferred):
    $at = Apache::AuthTkt->new(
        conf => '/etc/httpd/conf.d/auth_tkt.conf',
    );
    # OR:
    $at = Apache::AuthTkt->new(
        secret => '818f9c9d-91ed-4b74-9f48-ff99cfe00a0e',
    );

    # Generate ticket
    $ticket = $at->ticket(uid => $username, ip_addr => $ip_addr);

    # Or generate cookie containing ticket
    $cookie = $at->cookie(
        uid => $username, 
        cookie_name => 'auth_tkt',
        cookie_domain => 'www.openfusion.com.au',
    );

    # Access the shared secret
    $secret = $at->secret();
    # If using the 'conf' constructor above, all other TKTAuth attributes 
    #   are also available e.g.:
    print $at->cookie_name(), $at->ignore_ip(), $at->request_ssl();

    # Report error string
    print $at->errstr;


=head1 INTRODUCTION

Apache::AuthTkt is a module for generating authentication tickets
for use with the 'mod_auth_tkt' apache module. Tickets are typically
generated by a CGI/mod_perl page when a user has been authenticated.
The ticket contains a username/uid for the authenticated user, and
often also the IP address they authenticated from, a set of
authorisation tokens, and any other user data required. The ticket
also includes an MD5 hash of all the included user data plus a shared
secret, so that tickets can be validated by mod_auth_tkt without
requiring access to the user repository.

See http://www.openfusion.com.au/labs/mod_auth_tkt for mod_auth_tkt
itself.


=head1 DESCRIPTION

=head2 CONSTRUCTOR

An Apache::AuthTkt object is created via a standard constructor
with named arguments. The preferred form is to point the constructor
to the apache config file containing the mod_auth_tkt TKTAuthSecret
directive, from which Apache::AuthTkt will parse the shared secret
it needs, as well as any additional TKTAuth* directives it finds:

    $at = Apache::Tkt->new(
        conf => '/etc/httpd/conf/auth_tkt.conf',
    );

Alternatively, you can pass the mod_auth_tkt shared secret (the 
TKTAuthSecret value) explicitly to the constructor: 

    $at = Apache::AuthTkt->new(
        secret => '818f9c9d-91ed-4b74-9f48-ff99cfe00a0e',
    );


=head2 ACCESSORS

If the 'conf' form of the constructor is used, Apache::AuthTkt parses
all additional TKTAuth* directives it finds there and stores them in
additional internal attributes. Those values are available via 
accessors named after the relevant TKTAuth directive (with the 'TKTAuth'
prefix dropped and converted to lowercase underscore format) i.e.

    $at->secret()
    $at->cookie_name()
    $at->back_cookie_name()
    $at->back_arg_name()
    $at->domain()
    $at->cookie_expires()
    $at->login_url()
    $at->timeout_url()
    $at->unauth_url()
    $at->timeout()
    $at->timeout_refresh()
    $at->token ()
    $at->guest_login()
    $at->ignore_ip()
    $at->require_ssl()


=head2 TICKET GENERATION

Tickets are generated using the ticket() method with named parameters:

    # Generate ticket
    $ticket = $at->ticket(uid => $username);

Ticket returns undef on error, with error information available via
the errstr() method:
 
    $ticket = $at->ticket or die $at->errstr;

ticket() accepts the following arguments, all optional:

=over 4

=item uid

uid, username, or other user identifier for this ticket. There is no
requirement that this be unique per-user. Default: 'guest'.

=item ip_addr

IP address associated with this ticket. Default: if $at->ignore_ip
is true, then '0.0.0.0', otherwise $ENV{REMOTE_ADDR};

=item tokens

A comma-separated list of tokens associated with this user. Typically
only used if you are using the mod_auth_tkt TKTAuthToken directive.
Default: none.

=item data

Arbitrary user data to be stored for this ticket. This data is included
in the MD5 hash check. Default: none.

=item base64

Flag used to indicate whether to base64-encode the ticket. Default: 1.

=item ts

Explicitly set the timestamp to use for this ticket. Only for testing!

=back


As an alternative to ticket(), the cookie() method can be used to 
return the generated ticket in cookie format. cookie() returns undef 
on error, with error information available via the errstr() method:

    $cookie = $at->cookie or die $at->errstr;

cookie() supports all the same arguments as ticket(), plus the 
following:

=over 4

=item cookie_name

Cookie name. Should match the TKTAuthCookieName directive, if you're
using it. Default: $at->cookie_name, or 'auth_tkt'.

=item cookie_domain

Cookie domain. Should match the TKTAuthDomain directive, if you're
using it. Default: $at->domain.

=item cookie_path

Cookie path. Default: '/'.

=item cookie_secure

Flag whether to set the 'secure' cookie flag, so that the cookie is 
returned only in HTTPS contexts. Default: $at->require_ssl, or 0.

=back


=head1 AUTHOR

Gavin Carr <gavin@openfusion.com.au>


=head1 COPYRIGHT

Copyright 2001-2005 Open Fusion Pty Ltd. All Rights Reserved.

This program is free software. You may copy or redistribute it under the 
same terms as perl itself.

=cut


# arch-tag: 66306185-1c1a-4190-8edc-46f631719e78
# vim:sw=4
