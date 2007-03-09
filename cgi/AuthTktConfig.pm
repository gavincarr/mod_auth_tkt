#
# Config settings for mod_auth_tkt CGI scripts
# 
# Customise as required
#

package AuthTktConfig;

use strict;

# CSS stylesheet to use (optional)
our $STYLESHEET = 'tkt.css';

# Page title (optional)
our $TITLE = '';

# Fixed back location, overriding any set via back cookie or back arg
our $FIXED_BACK_LOCATION = '';

# Default back location, if none set via back cookie or back arg
our $DEFAULT_BACK_LOCATION = '';

# Boolean flag, whether to fallback to HTTP_REFERER for back location
our $BACK_REFERER = 1;

# For autologin, mode to fallback to if autologin fails ('login' or 'guest')
our $AUTOLOGIN_FALLBACK_MODE = 'login';

# Additional cookies to clear on logout e.g. PHPSESSID
our @NUKE_COOKIES = qw();

# Debug flag
our $DEBUG = 0;

# Username/password validation for login mode
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
our $validate_sub = \&validate;

# For guest mode (if used), setup guest username
#   Could use a counter or a random suffix etc.
sub guest_user { return 'guest' }
our $guest_sub = \&guest_user;

1;

