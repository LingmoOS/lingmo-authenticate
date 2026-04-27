# Run tests in check section
# disable for bootstrapping
%bcond_with check
%global prefix  /usr

%global with_debug 1

%if 0%{?with_debug}
%global debug_package   %{nil}
%endif


Name:           deepin-authenticate
Version:        1.2.6
Release:        1
Summary:        Used to adapt fingerprint, face and other authentication methods
License:        GPLv3
URL:            %{gourl}
Source0:        %{name}-%{version}.orig.tar.xz

BuildRequires:  compiler(go-compiler)
BuildRequires:  iso-codes
BuildRequires:  pkgconfig(gnome-keyring-1)
BuildRequires:  pkgconfig(libsystemd)
BuildRequires:  pam-devel
BuildRequires:  json-c-devel
BuildRequires:  pkgconfig(gio-2.0)
BuildRequires:  go-gir-generator
BuildRequires:  pkgconfig(gdk-3.0)
BuildRequires:  pkgconfig(gdk-x11-3.0)
BuildRequires:  pkgconfig(gdk-pixbuf-xlib-2.0)
BuildRequires:  pkgconfig(libpulse)
BuildRequires:  gocode
BuildRequires:  deepin-gettext-tools
BuildRequires:  golang-github-linuxdeepin-go-dbus-factory-devel
BuildRequires:  go-lib-devel

%description
In order to unify the authentication interface,
this interface is designed to adapt to fingerprint, face and other authentication methods.

%prep
%setup -q
patch -p1 < rpm/0001-fix-for-UonioTech.patch

%build
BUILDID="0x$(head -c20 /dev/urandom|od -An -tx1|tr -d ' \n')"
export GOPATH=/usr/share/gocode
%make_build GO_BUILD_FLAGS=-trimpath GOBUILD="go build -compiler gc -ldflags \"-B $BUILDID\""

%install
export GOPATH=/usr/share/gocode
%make_install PAM_MODULE_DIR=%{_libdir}/security GOBUILD="go build -compiler gc -ldflags \"-B $BUILDID\""

%find_lang deepin-authentication

%files -f deepin-authentication.lang
%doc README.org
%license

%{_prefix}/lib/deepin-authenticate/deepin-authentication
%{_prefix}/share/deepin-authentication/allowlist
%{_var}/lib/deepin/authenticate/blacklist
%{_var}/lib/deepin/authenticate/pam-modules
%{_prefix}/lib/systemd/system/deepin-authenticate.service
%{_datadir}/dbus-1/system.d/*.conf
%{_datadir}/dbus-1/system-services
%{_sysconfdir}/pam.d/deepin_pam_unix
%{_localstatedir}/lib/deepin/authenticate/config.json
%{_datadir}/polkit-1/actions/*.policy
%{_libdir}/security/pam_deepin_authentication.so


%changelog
* Thu Mar 23 2021 uoser <uoser@uniontech.com> - 1.2.6-1
- Update to 1.2.6