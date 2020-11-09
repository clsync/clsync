#
# author: Enrique Martinez <enmaca@hotmail.com>
# license: GPL-3+
#
Summary:	Live sync tool based on inotify
Name: 		clsync
Version:	@VERSION@
Release:	@BUILDNUM@
License: 	GPL-3+
Group:		Applications/System
URL: 		https://github.com/clsync/clsync
Source0: 	clsync-%{version}.tar.gz
Source1: 	clsync.init
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
BuildRequires: 	glib2-devel
BuildRequires:	autoconf

%description
live sync tool based on inotify, written in GNU C
Clsync recursively watches for source directory and executes external
program to sync the changes. Clsync is adapted to use together with rsync.
This utility is much more lightweight than competitors and supports such
features as separate queue for big files, regex file filter,
multi-threading.

%package devel
Summary: Development Files for clsync
Group: Applications/System
Requires: clsync = %{version}-%{release}

%description devel
live sync tool based on inotify, written in GNU C
Clsync recursively watches for source directory and executes external
program to sync the changes. Clsync is adapted to use together with rsync.
This utility is much more lightweight than competitors and supports such
features as separate queue for big files, regex file filter,
multi-threading.

%prep
%setup

%build
autoreconf -if
%configure
make

%install
make install DESTDIR=%{buildroot}
install -D -p -m 0750 %{SOURCE1} %{buildroot}/etc/init.d/clsync
mkdir -p %{buildroot}/etc/clsync/rules

cat > %{buildroot}/etc/clsync/clsync.conf <<EOF
# This configuration is a simple test
# set appropriate dirs for testing yourself :)
[default]
#watch-dir = /var/tmp/clsync/from
#destination-dir = /var/tmp/clsync/to
rules-file = /etc/clsync/rules/default
mode = rsyncdirect
sync-handler = /usr/bin/rsync
background = 1
syslog = 1
full-initialsync = 1
retries = 3
EOF

cat > %{buildroot}/etc/clsync/rules/default <<EOF
-d^[Dd]ont[Ss]ync\$
+*.*
EOF

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{_bindir}/*
%doc %{_docdir}/* 
%doc %{_mandir}/man1/clsync.1.gz
%config(noreplace) /etc/clsync/clsync.conf
/etc/clsync/rules/default
/etc/init.d/clsync


%files devel
%{_includedir}/clsync/*

%changelog
* Sun Nov 08 2020 Andrew A. Savchenko <bircoph@gmail.com> - 0.4.5-1
- Fix build on musl, avoid glibc-specific code.
- Do not ignore *-{uid,gid} settings if no CAPABILITIES_SUPPORT.
- Fix potential buffer problems in string and memory operations.
- Add LTO support, support -fwhole on E2K arch.
- Optimize checks using (un)likely.
- Autogenerate program.h
- Fix doxygen issues.
- Fix build using autoconf-2.70.

* Sat Apr 25 2020 Andrew A. Savchenko <bircoph@gmail.com> - 0.4.4-1
- Add --sync-on-quit option.
- Support TMPDIR environment variable.
- Multiple bug fixes.

* Thu Sep 29 2016 Andrew A. Savchenko <bircoph@gmail.com> - 0.4.2-1
- Maintenance release, many bug fixes

* Thu Nov 6 2014 Dmitry Yu Okunev <dyokunev@ut.mephi.ru> - 0.4-1
- A lot of fixes

* Thu Jan 9 2014 Dmitry Yu Okunev <dyokunev@ut.mephi.ru> - 0.3-1
- Added support of control socket

* Thu Oct 24 2013 Barak A. Pearlmutter <bap@debian.org> - 0.2.1-1
- New upstream version

* Fri Oct 11 2013 Barak A. Pearlmutter <bap@debian.org> - 0.1-2
- Tweak debian/watch to ignore debian releases

* Sat Sep 07 2013 Barak A. Pearlmutter <bap@debian.org> - 0.1-1
- Initial release (Closes: #718769 )
