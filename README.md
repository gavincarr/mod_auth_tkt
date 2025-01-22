Notice
------

This software is unmaintained. Please use a fork or another project.


Introduction
------------

See the INSTALL file for installation instructions.

  *NOTE: this version of mod_auth_tkt (2.0.x) works with Apache
   1.3.x, 2.0.x, and 2.2.x. The older mod_auth_tkt 1.3.x is now
   deprecated, and all users are encouraged to upgrade.*

mod_auth_tkt is a lightweight cookie-based authentication module for
Apache, written in C. It implements a single-signon framework that works
across multiple apache instances and multiple machines. The actual
authentication is done by a user-supplied CGI or script in whatever
language you like (examples are provided in Perl), meaning you can
authenticate against any kind of user repository you can access
(password files, ldap, databases, etc.)

mod_auth_tkt supports inactivity timeouts (including the ability to
control how aggressively the ticket is refreshed), the ability to
include arbitrary user data within the cookie, configurable cookie names
and domains, and token-based access to subsections of a site.

mod_auth_tkt works by checking incoming Apache requests for a (user-
defined) cookie containing a valid authentication ticket. The ticket is
checked by generating an MD5 checksum for the username and any
(optional) user data from the ticket together with the requesting IP
address and a shared secret available to the server. If the generated
MD5 checksum matches the ticket's checksum, the ticket is valid and the
request is authorised. Requests without a valid ticket are redirected to
a configurable URL which is expected to validate the user and generate a
ticket for them. This package includes a Perl module for generating the
cookies; implementations for other environments should be relatively
straightforward.



Pros and Cons
-------------

The mod_auth_tkt scheme has several advantages and only one significant
disadvantage:

Advantages -

1. Usable on any apache webserver: because it's written in C using only
the Apache C API, mod_auth_tkt should be usable on the simplest stripped
down Apache server - no mod_perl, mod_php, or servlets required.
mod_auth_tkt's only requirement is that the Apache supports DSO (Dynamic
Shared Objects).

2. Single-signon across Apaches and machines, including mixed
environments: mod_auth_tkt enables a user to login once and then be
seamlessly authorised across multiple Apaches or machines. Mixed
environments work fine too - lightweight static HTML Apache with heavier
mod_perl/mod_php/servlet enabled Apache, or a mixed Unix/Windows
environment. Only requirements are a shared secret across all the
servers.

3. Pluggable authentication and authorisation: mod_auth_tkt hands off
the authentication and authorisation problem to the URL of your choice.
This means that you can use whatever technology (CGI, Perl, PHP, ASP,
Java etc.) and whatever repositories (passwd files, LDAP, NIS, RDBMS,
radius, or any combination thereof) you like - as long as the
authorising page or script generates a valid ticket for a valid user
everything should work just fine.

4. Drop-in replacement for Basic Authentication: mod_auth_tkt sets
the Basic Authentication REMOTE_USER environment variable on authorised
requests, so that existing scripts that work with Basic Authentication
should work unchanged in a mod_auth_tkt environment.

5. No server-side storage requirements: because cookies are basically
a client-side storage technology, there are no storage requirements
on the server side - no session database is required (although you're
free to use one if it already exists).

6. Supports cross-domain authentication (as of version 1.3.8): although
cookies are domain specific, the newest version of mod_auth_tkt allows
initial tickets to be passed via URLs, allowing single-signon across
completely unrelated domains (www.foo.com and www.bar.com).


Disadvantages -

1. Requires cookies: browsers without cookie support will never have a
valid ticket and will therefore never be authorised by mod_auth_tkt.
There are no current plans to support non-cookie-based authentication.




Protocol Details
----------------

1. Login procedure (by user script/CGI)

1.1 User logs in by supplying user credentials to server-side
    login module. Login module is implemented e.g., as CGI or servlet.

1.2 Login module has access to a login database that has following
    information: user credentials and additional information such
    as user class/groups etc.

1.3 If login module finds that user credentials supplied matches
    the ones in database, an authentication cookie is constructed.

1.4 Contents of authentication cookie: user ID, client IP address,
    timestamp, optional token list, optional user data, plus an
    MD5 checksum to ensure the integrity of the cookie. The MD5
    checksum is generated from following information:
     - shared secret
     - user ID
     - client IP address
     - timestamp
     - token list, if supplied
     - user data, if supplied

1.5 The basic format of the ticket / authentication cookie value is
    as follows:

    ticket := <MD5-checksum> <timestamp> <uid> ['\0' <tokens>] ['\0' <user-data>]

    tokens := ! <token1> [ , <token2> ... ]

    user-data := ! <arbitrary-user-data>




2. Request authentication by mod_auth_tkt

2.1 If no authentication cookie is present in a request, request is
    redirected to a configurable login URL.

2.2 If authentication cookie is present and timeout checking is
    enabled, timestamp in the cookie is compared with the current time
    on the server. If the cookie has expired, request is redirected to a
    configurable timeout URL.

2.3 If authentication cookie is present and not expired, MD5 checksum is
    generated as described in 1.4. The MD5 checksum in cookie is
    compared with the one generated. If they match the user is
    successfully authenticated.

2.4 If a TKTAuthToken is also required for this url/area, mod_auth_tkt
    will then check the first field of the user_data (which has been
    checked via the MD5 checksum in the previous step) for a comma-
    separated list of tokens for this user. If the required token is
    not found in this list, the request is redirected to a configurable
    unauthorised URL.

2.4 Upon successful authentication authentication mod_auth_tkt sets
    environment variables for user ID and user data. User data is also
    placed in query string.

2.5 If authentication fails, request is redirected as in 2.1.

2.6 Upon redirection in 2.1, 2.2 or 2.4 mod_auth_tkt attempts to pass
    the requested URL as a 'back' link so that after checking user
    credentials login module can bounce the request back again. If
    the TktAuthBackCookieName parameter is set, mod_auth_tkt will set
    a cookie with that name to hold this link; otherwise it will pass
    it as a GET parameter to the authenticating URL (back=<url>).


Cookie Format
-------------

The TKTAuthCookieName cookie is constructed using following algorithm:

('+' is concatenation operation)

cookie := digest + hextimestamp + user_id + '!' + user_data

or if using tokens:

cookie := digest + hextimestamp + user_id + '!' + token_list + '!' + user_data

digest := MD5(digest0 + key)

digest0 := MD5(iptstamp + key + user_id + '\0' + token_list + '\0' + user_data)

iptstamp is a 8 bytes long byte array, bytes 0-3 are filled with
client's IP address as a binary number in network byte order, bytes
4-7 are filled with timestamp as a binary number in network byte
order.

hextimestamp is 8 character long hexadecimal number expressing
timestamp used in iptstamp.

token_list is an optional comma-separated list of access tokens
for this user. This list is checked if TKTAuthToken is set for a
particular area.

user_data is optional



Credits and Licence
-------------------

This is the Open Fusion version of the mod_auth_tkt Apache module.
mod_auth_tkt was originally written by Raimondas Kiveris for Liquid
Digital Information Systems, Inc. (see http://www.ldis.com/tkt_auth/),
and further developed by Nelio Alves Pereira Filho
(see http://www.ime.usp.br/~nelio/software/apache/). This version is
the work of Gavin Carr of Open Fusion Pty. Ltd. (Australia), and the
contributors cited in the CREDITS file in the distribution.

See the [LICENSE](LICENSE) file for licensing information.

