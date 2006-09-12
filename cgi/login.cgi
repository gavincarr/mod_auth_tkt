#!/usr/bin/perl -w
#
# mod_auth_tkt sample login script - runs as a vanilla CGI, under 
#   mod_perl 1 via Apache::Registry, and under mod_perl2 via 
#   ModPerl::Registry.
#
# This script can run in a few different modes, depending on how it is 
#   named. Copy the script to a cgi-bin area, and create appropriately 
#   named symlinks to access the different behaviours. 
# Modes:
#   - login mode (default): request a username and password and test via
#     $validate_sub - if successful, issue an auth ticket and redirect to 
#     the back location
#   - guest mode ('guest.cgi'): automatically issues an auth ticket a 
#     special username (as defined in $guest_sub, default 'guest'), and 
#     redirect to the back location (now largely obsolete - use 
#     TKTAuthGuestLogin instead)
#   - autologin mode ('autologin.cgi'): [typically used to allow tickets 
#     across multiple domains] if no valid auth ticket exists, redirect
#     to the login (or guest) version; otherwise automatically redirect 
#     to the back location passing the current auth ticket as a GET 
#     argument. mod_auth_tkt (>= 1.3.8) will turn this new ticket into 
#     an auth cookie for the new domain if none already exists.
#

use File::Basename;
use lib dirname($ENV{SCRIPT_FILENAME});
use Apache::AuthTkt 0.03;
use CGI qw(:standard);
use CGI::Cookie;
use URI::Escape;
use URI;
use strict;

# ------------------------------------------------------------------------
# Configure this section to taste

# CSS stylesheet to use (optional)
my $STYLESHEET = 'tkt.css';
# Page title (optional)
my $TITLE = '';
# For autologin, mode to fallback to if autologin fails ('login' or 'guest')
my $AUTOLOGIN_FALLBACK_MODE = 'login';
# Boolean flag, whether to fallback to HTTP_REFERER for back link
my $BACK_REFERER = 1;

# For login mode (if used), setup username/password validation
#   (modify or point $validate_sub somewhere appropriate).
# The validation routine should return a true value (e.g. 1) if the 
#   given username/password combination is valid, and a false value
#   (e.g. 0) otherwise.
# This version uses Apache::Htpasswd and a standard htpasswd file.
sub validate
{
  my ($username, $password) = @_;
  require Apache::Htpasswd;
  my $ht = Apache::Htpasswd->new({ 
    passwdFile => '/etc/httpd/conf/htpasswd', ReadOnly => 1 });
  return $ht->htCheckPassword($username, $password);
}
my $validate_sub = \&validate;

# For guest mode (if used), setup guest username
#   Could use a counter or a random suffix etc.
sub guest_user
{
  return 'guest';
}
my $guest_sub = \&guest_user;

# ------------------------------------------------------------------------
# Main code begins
my $debug = 0;
my $at = Apache::AuthTkt->new(conf => $ENV{MOD_AUTH_TKT_CONF});
my $q = CGI->new;
my ($server_name, $server_port) = split /:/, $ENV{HTTP_HOST} if $ENV{HTTP_HOST};
$server_name ||= $ENV{SERVER_NAME} if $ENV{SERVER_NAME};
$server_port ||= $ENV{SERVER_PORT} if $ENV{SERVER_PORT};
my $AUTH_DOMAIN = $at->domain || $server_name;
my @auth_domain = $AUTH_DOMAIN ? ( -domain => $AUTH_DOMAIN ) : ();
my $ticket = $q->cookie($at->cookie_name);
my $probe = $q->cookie('auth_probe');
my $back = $q->cookie($at->back_cookie_name) if $at->back_cookie_name;
my $have_cookies = $ticket || $probe || $back || '';
$back ||= $q->param($at->back_arg_name) if $at->back_arg_name;
$back ||= $ENV{HTTP_REFERER} if $ENV{HTTP_REFERER} && $BACK_REFERER;
if ($back && $back =~ m!^/!) {
  my $hostname = $server_name;
  my $port = $server_port;
  $hostname .= ':' . $port if $port && $port != 80 && $port != 443;
  $back = sprintf "http%s://%s%s", ($port == 443 ? 's' : ''), $hostname, $back;
} elsif ($back && $back !~ m/^http/i) {
  $back = 'http://' . $back;
}
$back = uri_unescape($back) if $back && $back =~ m/^https?%3A%2F%2F/;
my $back_esc = uri_escape($back) if $back;
my $back_html = escapeHTML($back) if $back;

my ($fatal, @errors);
my ($mode, $location, $suffix) = fileparse($ENV{SCRIPT_NAME}, '\.cgi', '\.pl');
$mode = 'login' unless $mode eq 'guest' || $mode eq 'autologin';
my $self_redirect = $q->param('redirect') || 0;
my $username = lc($q->param('username'));
my $password = $q->param('password');
my $timeout = $q->param('timeout');
my $unauth = $q->param('unauth');
my $ip_addr = $at->ignore_ip ? undef : $ENV{REMOTE_ADDR};
my $redirected = 0;

# ------------------------------------------------------------------------
# Set the auth cookie and redirect to $back
my $set_cookie_redirect = sub {
  my ($tkt, $back) = @_;
  my @expires = $at->cookie_expires ? 
    ( -expires => sprintf("+%ss", $at->cookie_expires) ) :
    ();
  my $cookie = CGI::Cookie->new(
    -name => $at->cookie_name,
    -value => $tkt, 
    -path => '/',
    -secure => $at->require_ssl,
    @expires,
    @auth_domain,
  );

  # If no $back, just set the auth cookie and hope for the best
  if (! $back) {
    print $q->header( -cookie => $cookie );
    print $q->start_html, $q->p(Login successful), $q->end_html;
    return 0;
  }

  # Set (local) cookie, and redirect to $back
  print $q->header( -cookie => $cookie );
  return 0 if $debug;

  my $b = URI->new($back);
  # If $back domain doesn't match $AUTH_DOMAIN, pass ticket via back GET param
  my $domain = $AUTH_DOMAIN || $server_name;
  if ($b->host !~ m/\b$domain$/i) {
    $back .= $b->query ? '&' : '?';
    $back .= $at->cookie_name . '=' . $tkt;
  }

  # For some reason, using a Location: header doesn't seem to then see the 
  #   cookie, but a meta refresh one does - weird
  print $q->start_html(
    -head => meta({ -http_equiv => 'refresh', -content => "0;URL=$back" }),
    ), 
    $q->end_html;
  return 1;
};

# ------------------------------------------------------------------------
# Actual processing

# If no cookies found, first check whether cookies are supported
if (! $have_cookies) {
  # If this is a self redirect warn the user about cookie support
  if ($self_redirect) {
    $fatal = "Your browser does not appear to support cookies or has cookie support disabled.<br />\nThis site requires cookies - please turn cookie support on or try again using a different browser.";
  }
  # If no cookies and not a redirect, redirect to self to test cookies
  else {
    my $extra = '';
    $extra .= 'timeout=1' if $timeout;
    $extra .= 'unauth=1' if $unauth;
    $extra = "&$extra" if $extra;
    print $q->header(
      -cookie => CGI::Cookie->new(-name => 'auth_probe', -value => 1, @auth_domain),
    );
    # For some reason, a Location: redirect doesn't seem to then see the cookie,
    #   but a meta refresh one does - go figure
    print $q->start_html(
      -head => meta({
        -http_equiv => 'refresh', -content => ("0;URL=" . sprintf("%s%s%s?redirect=%s&%s=%s%s",
          $location, $mode, $suffix, $self_redirect + 1, $at->back_arg_name, 
          $back_esc || '', $extra))
    }));
    $redirected = 1;
  }
}

elsif ($mode eq 'autologin') {
  # If we have a ticket, redirect to $back, including ticket as GET param
  if ($ticket && $back && ! $timeout) {
    my $b = URI->new($back);
    $back .= $b->query ? '&' : '?';
    $back .= $at->cookie_name . '=' . $ticket;
    print $q->redirect($back);
    $redirected = 1;
  }
  # Can't autologin - change mode to either guest or login
  else {
    $mode = $AUTOLOGIN_FALLBACK_MODE;
  }
}

unless ($fatal || $redirected) {
  if (! $at) {
    $fatal = "AuthTkt error: " . $at->errstr;
  }
  elsif ($mode eq 'login') {
    if ($username && $validate_sub->($username, $password)) {
#     my $user_data = join(':', encrypt($password), time(), $ip_addr);
      my $user_data = join(':', time(), $ip_addr);    # Optional
      my $tkt = $at->ticket(uid => $username, data => $user_data, ip_addr => $ip_addr, debug => $debug);
      if (! @errors) {
        $redirected = $set_cookie_redirect->($tkt, $back);
        $fatal = "Login successful.";
      }
    }
    elsif ($username) {
      push @errors, "Invalid username or password.";
    }
  }

  elsif ($mode eq 'guest') {
    # Generate a guest ticket and redirect to $back
    my $tkt = $at->ticket(uid => $guest_sub->(), ip_addr => $ip_addr);
    if (! @errors) {
      $redirected = $set_cookie_redirect->($tkt, $back);
      $fatal = "No back link found.";
    }
  }
}

my @style = $STYLESHEET ? ('-style' => { src => $STYLESHEET }) : ();
$TITLE ||= "\u$mode Page";
unless ($redirected) {
  # If here, either some kind of error or a login page
  if ($fatal) {
    print $q->header,
      $q->start_html(
        -title => $TITLE,
        @style,
      );
  }
  else {
    push @errors, qq(Your session has timed out.) if $timeout;
    push @errors, qq(You are not authorised to access this area.) if $unauth;
    print $q->header,
      $q->start_html(
        -title => $TITLE,
        -onLoad => "getFocus()",
        @style,
        -script => qq(
function getFocus() {
  document.forms[0].elements[0].focus();
  document.forms[0].elements[0].select();
}));
  }
  print <<EOD;
<div align="center">
<h1>$TITLE</h1>
<p class="warning">Authorized Use Only</p>
EOD

  if ($debug) {
    my $cookie_name = $at->cookie_name;
    my $back_cookie_name = $at->back_cookie_name || '';
    my $back_arg_name = $at->back_arg_name || '';
    my $cookie_expires = $at->cookie_expires || 0;
    print <<EOD;
<pre>
server_name: $server_name
server_port: $server_port
domain: $AUTH_DOMAIN
mode: $mode
suffix: $suffix
cookie_name: $cookie_name
cookie_expires: $cookie_expires
back_cookie_name: $back_cookie_name
back_arg_name: $back_arg_name
back: $back
back_esc: $back_esc
back_html: $back_html
have_cookies: $have_cookies
ip_addr: $ip_addr
</pre>
EOD
  }

  if ($fatal) {
    print qq(<p class="error">$fatal</p>\n);
  }

  else {
    print qq(<p class="error">\n), join(qq(<br />\n), @errors), "</p>\n"
      if @errors;
    print <<EOD;
<form name="login" method="post" action="$mode$suffix">
<table border="0" cellpadding="5">
<tr><th>Username:</th><td><input type="text" name="username" /></td></tr>
<tr><th>Password:</th><td><input type="password" name="password" /></td></tr>
<tr><td colspan="2" align="center"> 
<input type="submit" value="Login" />
</td></tr>
</table>
EOD
    print qq(<input type="hidden" name="back" value="$back_html" />\n) if $back_html;
    print qq(</form>\n);
}

  print qq(<p><a href="$back_html">Previous Page</a></p>\n) if $back_html;
  print <<EOD;
</div>
</body>
</html>
EOD
}

# arch-tag: 1cac856d-534c-4c81-9e9a-34e39d26f4f2
# vim:sw=2:sm:cin

