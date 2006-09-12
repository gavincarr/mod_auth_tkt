Upgrading from mod_auth_tkt version 1.3.x to version 2.0.x
==========================================================

In general, upgrading should be a non-issue - just recompile and reinstall
mod_auth_tkt on each of your apache instances, both apache 1.3.x and 
apache 2.0.x.

The only gotcha is that the ticket format has changed (due to a 
vulnerability in the previous format), so tickets produced using the old
TktUtil.pm or tkt_cookie will not work with mod_auth_tkt 2.0.x - use the
new Apache::AuthTkt perl module instead (or see the contrib directory
for possible alternatives).

Also, the C tkt_cookie executable for generating cookies has been removed
from this version due to additional vulnerabilities and the maintenance 
overhead. If you used that, you'll have to use the Perl cgi scripts 
instead, or roll your own solution.

