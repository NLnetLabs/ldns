Summary: Lowlevel DNS(SEC) library with DNS tools
Name: ldns
Version: 1.1.0
Release: 1
License: BSD
Url: http://www.nlnetlabs.nl/%{name}/
Source: http://www.nlnetlabs.nl/downloads/%{name}-%{version}.tar.gz
Group: System Environment/Libraries
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Requires: openssl, libpcap
BuildRequires: libtool, autoconf, automake, gcc-c++, openssl-devel, doxygen, perl

%description
ldns is a library with the aim to simplify DNS programing in C. All
lowlevel DNS/DNSSEC operations are supported. We also define a higher
level API which allows a programmer to (for instance) create or sign
packets. 

The drill tool helps debug DNS by sending packets to servers, like 'dig'.
Example DNS tools are included that sign zone files, generate keys, 
send dynamic update packets, find mx info, sort zone files and more.

%package devel
Summary: Development package that includes the ldns header files
Group: Development/Libraries
Requires: %{name} = %{version}-%{release}, openssl-devel

%description devel
The devel package contains the ldns library and the include files

%prep
rm -rf %{buildroot}
%setup -q 
libtoolize
autoreconf
(cd drill; autoreconf)
(cd examples; autoreconf)

%build
%configure
%{__make} %{?_smp_mflags}
(cd drill; %configure; %{__make} %{?_smp_mflags})
(cd examples; %configure; %{__make} %{?_smp_mflags})
%{__make} %{?_smp_mflags} doc

%install
rm -rf %{buildroot}
export DESTDIR=%{buildroot}
%{__make} install
(cd drill; %{__make} install)
(cd examples; %{__make} install)

%clean
rm -rf %{buildroot}

%files 
%defattr(-,root,root)
%{_libdir}/libldns*so
%{_bindir}/drill
%{_bindir}/ldns*
%doc README LICENSE TODO 
%doc %{_mandir}/man1/drill*
%doc %{_mandir}/man1/ldns*

%files devel
%defattr(-,root,root,-)
%{_libdir}/libldns.la
%{_libdir}/libldns.a
%dir %{_includedir}/ldns/*
%doc doc/images doc/html doc/*.css
%doc doc/dns-lib-implementations doc/CodingStyle
%doc Changelog
%doc %{_mandir}/man3/ldns*

%pre

%post 
/sbin/ldconfig

%postun
/sbin/ldconfig

%changelog
* Tue Aug 15 2006 Wouter Wijngaards <wouter@nlnetlabs.nl> 1.1.0
- reworked for new Makefile. configure calls by build script.
- names the docs for devel package in more detail.

* Wed Oct  5 2005 Paul Wouters <paul@xelerance.com> 0.70_1205
- reworked for svn version

* Sun Sep 25 2005 Paul Wouters <paul@xelerance.com> - 0.70
- Initial version
