#!/usr/bin/perl -w
#
# mod_auth_tkt sample logout script
# 
# Note that this needs script needs to be available locally on all domains 
#   if using multiple domains (unlike login.cgi, which only needs to exist
#   on one domain).
#

use File::Basename;
use lib dirname($ENV{SCRIPT_FILENAME});
use Apache::AuthTkt 0.03;
use CGI qw(:standard);
use URI::Escape;
use URI;
use strict;

# ------------------------------------------------------------------------
# Configure this section to taste

# CSS stylesheet to use (optional)
my $STYLESHEET = 'tkt.css';
# Page title (optional)
my $TITLE = '';
# Boolean flag, whether to fallback to HTTP_REFERER for back link
my $BACK_REFERER = 1;
# Additional cookies to clear on logout e.g. PHPSESSID
my @NUKE_COOKIES = qw();

# ------------------------------------------------------------------------
# Main code begins
my $debug = 0;
my $at = Apache::AuthTkt->new(conf => $ENV{MOD_AUTH_TKT_CONF});
my $q = CGI->new;
my ($server_name, $server_port) = split /:/, $ENV{HTTP_HOST};
$server_name ||= $ENV{SERVER_NAME};
$server_port ||= $ENV{SERVER_PORT};
my $AUTH_DOMAIN = $at->domain || $server_name;
my $back = $q->cookie($at->back_cookie_name) if $at->back_cookie_name;
$back ||= $q->param($at->back_arg_name) if $at->back_arg_name;
$back ||= $ENV{HTTP_REFERER} if $BACK_REFERER;
if ($back && $back =~ m!^/!) {
  my $hostname = $server_name;
  my $port = $server_port;
  $hostname .= ':' . $port if $port && $port != 80 && $port != 443;
  $back = sprintf "http%s://%s%s", ($port == 443 ? 's' : ''), $hostname, $back;
} elsif ($back && $back !~ m/^http/i) {
  $back = 'http://' . $back;
}
$back = uri_unescape($back) if $back =~ m/^https?%3A%2F%2F/;
my $back_html = escapeHTML($back) if $back;

# Logout by resetting the auth cookie
my @cookies = cookie(-name => $at->cookie_name, -value => '', -expires => '-1h', 
    ($AUTH_DOMAIN ? (-domain => $AUTH_DOMAIN) : ()));
push @cookies, map { cookie(-name => $_, -value => '', -expires => '-1h') } @NUKE_COOKIES;

my $redirected = 0;
if ($back) {
  my $b = URI->new($back);
  # If $back domain doesn't match $AUTH_DOMAIN, add ticket reset to back
  if ($b->host !~ m/\b$AUTH_DOMAIN$/i) {
    $back .= $b->query ? '&' : '?';
    $back .= $at->cookie_name . '=';
  }

  if ($debug) {
    print $q->header(-cookie => \@cookies);
  }

  else {
    # Set (local) cookie, and redirect to $back
    print $q->header(
      -cookie => \@cookies,
#     -location => $back,
    );
    # For some reason, a Location: redirect doesn't seem to then see the cookie,
    #   but a meta refresh one does - weird
    print $q->start_html(
      -head => meta({
        -http_equiv => 'refresh', -content => "0;URL=$back"
    }));
    $redirected = 1;
  }
}

# If no $back, just set the auth cookie and hope for the best
else {
  print $q->header(-cookie => \@cookies);
}

my @style = $STYLESHEET ? ('-style' => { src => $STYLESHEET }) : ();
$TITLE ||= 'Logout Page';
unless ($redirected) {
  # If here, either some kind of error or no back ref found
  print $q->start_html(
      -title => $TITLE,
      @style,
    );
  print <<EOD;
<div align="center">
<h1>$TITLE</h1>
EOD
  if ($debug) {
    print <<EOD;
<pre>
back: $back
back_html: $back_html
</pre>
EOD
  }
  print <<EOD;
<p>You are now logged out.</p>
EOD
  print qq(<p><a href="$back_html">Previous Page</a></p>\n) if $back_html;
  print <<EOD;
</div>
</body>
</html>
EOD
}

# arch-tag: 09c96fc6-5119-4c79-8086-6c6b24951f96
# vim:sw=2:sm:cin

