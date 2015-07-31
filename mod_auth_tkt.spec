
# Use "--define='apache 1'" to build a 'mod_auth_tkt1' package for apache1
%define httpd httpd
%define name mod_auth_tkt
%if %{rhel} < 7
%define apxs /usr/sbin/apxs
%else
%define apxs /usr/bin/apxs
%endif
%{?apache:%define httpd apache}
%{?apache:%define name mod_auth_tkt1}
%{?apache:%define apxs /usr/sbin/apxs1}

%define perl_vendorlib %(eval "`perl -V:installvendorlib`"; echo $installvendorlib)

Summary: Lightweight ticket-based authentication module for Apache.
Name: %{name}
Version: 2.3.99b1
Release: 1%{?org_tag}%{?dist}
License: Apache
Group: Applications/System
Source: http://www.openfusion.com.au/labs/dist/mod_auth_tkt-%{version}.tar.gz
URL: http://www.openfusion.com.au/labs/mod_auth_tkt/
Buildroot: %_tmppath/%{name}-%{version}
Requires: %{httpd}
BuildRequires: %{httpd}-devel

%description
mod_auth_tkt provides lightweight, repository-agnostic, ticket-based
authentication for Apache. It implements a single-signon framework that
works across multiple apache instances and multiple machines. The actual
authentication requires a user-supplied CGI or script of some kind - see
the mod_auth_tkt-cgi package for perl cgi versions.

%package cgi
Release: 1%{?org_tag}%{?dist}
Summary: CGI scripts for mod_auth_tkt apache authentication modules.
Group: Applications/System
Requires: %{name} = %{version}

%description cgi
Perl CGI scripts for use with mod_auth_tkt.


%prep
%setup -n mod_auth_tkt-%{version}

%build
test %{debug} == 1 && DEBUG='--debug'
MOD_PERL=`rpm -q mod_perl | grep '^mod_perl' || /bin/true`
if [ -n "$MOD_PERL" -a %{test} == 1 ]; then
  ./configure --apxs=%{apxs} --test $DEBUG
  make
  make test
else
  ./configure --apxs=%{apxs} $DEBUG
  make
fi

%install
test "$RPM_BUILD_ROOT" != "/" && rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT%{_libdir}/%{httpd}/modules
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/%{httpd}/conf.d
#mkdir -p $RPM_BUILD_ROOT/usr/share/doc/%{name}-%{version}/cgi
mkdir -p $RPM_BUILD_ROOT/usr/share/doc/%{name}-%{version}/contrib
mkdir -p $RPM_BUILD_ROOT/var/www/auth
#mkdir -p $RPM_BUILD_ROOT/%{perl_vendorlib}/Apache
if [ %{httpd} == apache ]; then
  %{apxs} -i -n "auth_tkt" -S LIBEXECDIR=$RPM_BUILD_ROOT%{_libdir}/%{httpd}/modules src/mod_auth_tkt.so
else
  %{apxs} -i -n "auth_tkt" -S LIBEXECDIR=$RPM_BUILD_ROOT%{_libdir}/%{httpd}/modules src/mod_auth_tkt.la
fi
install -m 644 conf/02_auth_tkt.conf $RPM_BUILD_ROOT%{_sysconfdir}/%{httpd}/conf.d/
install -m 644 conf/auth_tkt_cgi.conf $RPM_BUILD_ROOT%{_sysconfdir}/%{httpd}/conf.d/
#cp cgi/Apache/* $RPM_BUILD_ROOT/%{perl_vendorlib}/Apache
#cp -pr cgi/* $RPM_BUILD_ROOT/usr/share/doc/%{name}-%{version}/cgi
#rm -rf $RPM_BUILD_ROOT/usr/share/doc/%{name}-%{version}/cgi/Apache
cp -pr cgi/* $RPM_BUILD_ROOT/var/www/auth
rm -rf $RPM_BUILD_ROOT/var/www/auth/Apache
cp -pr contrib/* $RPM_BUILD_ROOT/usr/share/doc/%{name}-%{version}/contrib
rm -rf $RPM_BUILD_ROOT/usr/share/doc/%{name}-%{version}/contrib/t
cp -pr README* INSTALL LICENSE CREDITS $RPM_BUILD_ROOT/usr/share/doc/%{name}-%{version}
cd doc
make DESTDIR=$RPM_BUILD_ROOT install

%clean
test "$RPM_BUILD_ROOT" != "/" && rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%{_libdir}/%{httpd}
#%{perl_vendorlib}/Apache/AuthTkt.pm
%doc /usr/share/doc/%{name}-%{version}
%attr(0640,root,apache) %config(noreplace) %{_sysconfdir}/%{httpd}/conf.d/02_auth_tkt.conf
/usr/share/man/*/*

%files cgi
%defattr(-,root,root)
%attr(0640,root,apache) %config(noreplace) %{_sysconfdir}/%{httpd}/conf.d/auth_tkt_cgi.conf
%config(noreplace)/var/www/auth/AuthTktConfig.pm
%config(noreplace)/var/www/auth/tkt.css
/var/www/auth/*.cgi

%changelog
* Fri Jul 31 2015 Gavin Carr <gavin@openfusion.com.au> 2.3.99b1-1
- Update to version 2.3.99b1, 2.4 release beta1.

* Fri Jul 10 2009 Gavin Carr <gavin@openfusion.com.au> 2.1.0
- Bump version number to 2.1.0 for final 2.1 release.

* Sat Mar 28 2009 Gavin Carr <gavin@openfusion.com.au> 2.0.99b2
- Bump version number to 2.0.99b2, second beta release of 2.1 branch.
- Fix bug with partial-cookie-names incorrectly matching.

* Thu Mar 05 2009 Gavin Carr <gavin@openfusion.com.au> 2.0.99b1
- Bump version number to 2.0.99b1, first beta release of 2.1 branch.
- Add support for SHA256 digests.
- Add TKTAuthSecretOld support.

* Fri Feb 27 2009 Gavin Carr <gavin@openfusion.com.au> 2.0.0-1
- Bump to final version 2.0.0.

* Fri Feb 27 2009 Gavin Carr <gavin@openfusion.com.au> 2.0.0-1
- Bump to final version 2.0.0.

* Tue Mar 04 2008 Gavin Carr <gavin@openfusion.com.au> 2.0.0rc4-1
- Bump to version 2.0.0rc4.

* Tue Mar 04 2008 Gavin Carr <gavin@openfusion.com.au> 2.0.0rc3-1
- Set explicit servername in t/TESTS to fix general test failures.
- Add explicit Apache 2.2 support.
- Add separate mod_auth_tkt-cgi package containing /var/www/auth CGI scripts.
- Factor out cgi config settings into AuthTktConfig.pm.
- Bump to version 2.0.0rc3.

* Wed Nov 28 2006 Gavin Carr <gavin@openfusion.com.au> 2.0.0rc2
- Bump to version 2.0.0rc2.

* Wed Nov 01 2006 Charlie Brady <charlie_brady@mitel.com> 2.0.0rc1-2
- Move Apache::AuthTkt into perl's vendorarch directory.

* Mon Apr 10 2006 Gavin Carr <gavin@openfusion.com.au> 2.0.0rc1
- Add mod_auth_tkt man page.
- Add TKTAuthDebug support, instead of compile-time debug flag.
- Add TKTAuthPostTimeoutURL support (Michael Peters).

* Mon Oct 24 2005 Gavin Carr <gavin@openfusion.com.au> 2.0.0b7
- Deprecate TKTAuthTimeoutMin, replacing with TKTAuthTimeout, using units like
  TKTAuthCookieExpires.
- Split out TKTAuthCookieSecure functionality from TKTAuthRequireSSL (Larry
  Lansing).
- Add TKTAuthCookieExpires directive for guest cookies and refreshes.
- Add TKTAuthGuestUser %U format support for UUIDs with Apache 2.
- Add TKTAuthGuestUser support for setting guest user explicitly.
- Fix URI and HTML escaping issues with cgi scripts (Viljo Viitanen).
- Update CGI scripts to get local settings via Apache::AuthTkt parse_conf values.
- Update Apache::AuthTkt to new version (0.03) with parse_conf support.
- Add server config merge support to allow global secrets with vhosts.

* Mon Aug 01 2005 Gavin Carr <gavin@openfusion.com.au> 2.0.0b6
- Update specfile to support basic building against apache 1.
- Fixed bug with non-base64 quoted ticket values not being parsed correctly.

* Tue Jun 14 2005 Gavin Carr <gavin@openfusion.com.au> 2.0.0b5
- Change back url formation to use Host header, not server name/port.
- Get cookie_match to skip empty cookies it finds (e.g. logout misconfigs).
- Add Ian Bicking's AuthTicket python class in contrib.
- Add TKTAuthGuestLogin support based on patch from Ian Bicking.
- Add DEBUG_VERBOSE support based on patch from Ian Bicking.
- Fixed bug with test harness not generating local module correctly.

* Mon May 30 2005 Gavin Carr <gavin@openfusion.com.au> 2.0.0b4
- Change build to include 'make test' only if mod_perl is available.

* Sat Apr 30 2005 Gavin Carr <gavin@openfusion.com.au> 2.0.0b3

* Thu Feb 21 2005 Gavin Carr <gavin@openfusion.com.au> 2.0.0b2
- Initial release.


