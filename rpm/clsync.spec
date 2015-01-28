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
URL: 		https://github.com/xaionaro/clsync
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
mkdir -p %{buildroot}/var/tmp/clsync/from
mkdir -p %{buildroot}/var/tmp/clsync/to
mkdir -p %{buildroot}/var/run/clsync

cat > %{buildroot}/etc/clsync/clsync.conf <<EOF
# This configuration is a simple test
[default]
watch-dir = /var/tmp/clsync/from
rules-file = /etc/clsync/rules/default
destination-dir = /var/tmp/clsync/to
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
%dir /var/tmp/clsync/from
%dir /var/tmp/clsync/to
%dir /var/run/clsync
%config(noreplace) /etc/clsync/clsync.conf
/etc/clsync/rules/default
/etc/init.d/clsync


%files devel
%{_includedir}/clsync/clsync.h
%{_includedir}/clsync/compilerflags.h
%{_includedir}/clsync/configuration.h
%{_includedir}/clsync/ctx.h
%{_includedir}/clsync/error.h
%{_includedir}/clsync/indexes.h
%{_includedir}/clsync/malloc.h
%{_includedir}/clsync/port-hacks.h


%changelog
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