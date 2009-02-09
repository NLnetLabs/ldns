Summary: Lowlevel DNS(SEC) library with API
Name: ldns
Version: 1.5.0
Release: 1%{?dist}
License: BSD
Url: http://www.nlnetlabs.nl/%{name}/
Source: http://www.nlnetlabs.nl/downloads/%{name}-%{version}.tar.gz
Group: System Environment/Libraries
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires: libtool, autoconf, automake, gcc-c++, openssl-devel, doxygen,
BuildRequires: perl libpcap-devel

%description
ldns is a library with the aim to simplify DNS programing in C. All
lowlevel DNS/DNSSEC operations are supported. We also define a higher
level API which allows a programmer to (for instance) create or sign
packets.

%package devel
Summary: Development package that includes the ldns header files
Group: Development/Libraries
Requires: %{name} = %{version}-%{release}, openssl-devel

%description devel
The devel package contains the ldns library and the include files

%prep
%setup -q 
# To built svn snapshots
#rm config.guess config.sub ltmain.sh
#libtoolize
#autoreconf

%configure --disable-rpath --with-sha2

%build

make %{?_smp_mflags}
(cd drill ; %configure --disable-rpath --with-ldns=%{buildroot}/lib/)
(cd examples ; %configure --disable-rpath --with-ldns=%{buildroot}/lib/)
( cd drill ; make %{?_smp_mflags} )
( cd examples ; make %{?_smp_mflags} )
make %{?_smp_mflags} doc

%install
rm -rf %{buildroot}

make DESTDIR=%{buildroot} INSTALL="%{__install} -p" install 
make DESTDIR=%{buildroot} INSTALL="%{__install} -p" install-doc

# don't package building script in doc
rm doc/doxyparse.pl
#remove doc stubs
rm -rf doc/.svn
#remove double set of man pages
rm -rf doc/man

# remove .la files
rm -rf %{buildroot}%{_libdir}/*.la
(cd drill ; make DESTDIR=%{buildroot} install)
(cd examples; make DESTDIR=%{buildroot} install)

%clean
rm -rf %{buildroot}

%files 
%defattr(-,root,root)
%{_libdir}/libldns*so.*
%{_bindir}/drill
%{_bindir}/ldns-*
%{_bindir}/ldnsd
%doc README LICENSE 
%{_mandir}/*/*

%files devel
%defattr(-,root,root,-)
%{_libdir}/libldns.a
%{_libdir}/libldns*so
%dir %{_includedir}/ldns
%{_includedir}/ldns/*.h
%doc doc Changelog README

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%changelog
* Mon Feb 09 1009 Jelte Jansen <jelte@nlnetlabs.nl> - 1.5.0
- Updated to 1.5.0

* Thu Feb 05 2009 Adam Tkac <atkac redhat com> - 1.4.0-3
- fixed configure flags

* Sat Jan 17 2009 Tomas Mraz <tmraz@redhat.com> - 1.4.0-2
- rebuild with new openssl

* Fri Nov  7 2008 Paul Wouters <paul@xelerance.com> - 1.4.0-1
- Updated to 1.4.0

* Wed May 28 2008 Paul Wouters <paul@xelerance.com> - 1.3.0-3
- enable SHA2 functionality

* Wed May 28 2008 Paul Wouters <paul@xelerance.com> - 1.3.0-2
- re-tag (don't do builds while renaming local repo dirs)

* Wed May 28 2008 Paul Wouters <paul@xelerance.com> - 1.3.0-1
- Updated to latest release

* Tue Feb 19 2008 Fedora Release Engineering <rel-eng@fedoraproject.org> - 1.2.2-3
- Autorebuild for GCC 4.3

* Wed Dec  5 2007 Paul Wouters <paul@xelerance.com> - 1.2.2-2
- Rebuild for new libcrypto

* Thu Nov 29 2007 Paul Wouters <paul@xelerance.com> - 1.2.2-1
- Upgraded to 1.2.2. Removed no longer needed race workaround

* Tue Nov 13 2007 Paul Wouters <paul@xelerance.com> - 1.2.1-4
- Try to fix racing ln -s statements in parallel builds

* Fri Nov  9 2007 Paul Wouters <paul@xelerance.com> - 1.2.1-3
- Added patch for ldns-read-zone that does not put @. in RRDATA

* Fri Oct 19 2007 Paul Wouters <paul@xelerance.com> - 1.2.1-2
- Use install -p to work around multilib conflicts for .h files

* Wed Oct 10 2007 Paul Wouters <paul@xelerance.com> - 1.2.1-1
- Updated to 1.2.1
- Removed patches that got moved into upstream

* Wed Aug  8 2007 Paul Wouters <paul@xelerance.com> 1.2.0-11
- Patch for ldns-key2ds to write to stdout
- Again remove extra set of man pages from doc
- own /usr/include/ldns (bug 233858)

* Wed Aug  8 2007 Paul Wouters <paul@xelerance.com> 1.2.0-10
- Added sha256 DS record patch to ldns-key2ds
- Minor tweaks for proper doc/man page installation.
- Workaround for parallel builds

* Mon Aug  6 2007 Paul Wouters <paul@xelerance.com> 1.2.0-2
- Own the /usr/include/ldns directory (bug #233858)
- Removed obsoleted patch
- Remove files form previous libtool run accidentally packages by upstream

* Mon Sep 11 2006 Paul Wouters <paul@xelerance.com> 1.0.1-4
- Commented out 1.1.0 make targets, put make 1.0.1 targets.

* Mon Sep 11 2006 Paul Wouters <paul@xelerance.com> 1.0.1-3
- Fixed changelog typo in date
- Rebuild requested for PT_GNU_HASH support from gcc
- Did not upgrade to 1.1.0 due to compile issues on x86_64

* Fri Jan  6 2006 Paul Wouters <paul@xelerance.com> 1.0.1-1
- Upgraded to 1.0.1. Removed temporary clean hack from spec file.

* Sun Dec 18 2005 Paul Wouters <paul@xelerance.com> 1.0.0-8
- Cannot use make clean because there are no Makefiles. Use hardcoded rm.

* Sun Dec 18 2005 Paul Wouters <paul@xelerance.com> 1.0.0-7
- Patched 'make clean' target to get rid of object files shipped with 1.0.0

* Sun Dec 13 2005 Paul Wouters <paul@xelerance.com> 1.0.0-6
- added a make clean for 2.3.3 since .o files were left behind upstream,
  causing failure on ppc platform

* Sun Dec 11 2005 Tom "spot" Callaway <tcallawa@redhat.com> 1.0.0-5
- minor cleanups

* Wed Oct  5 2005 Paul Wouters <paul@xelerance.com> 0.70_1205
- reworked for svn version

* Sun Sep 25 2005 Paul Wouters <paul@xelerance.com> - 0.70
- Initial version
