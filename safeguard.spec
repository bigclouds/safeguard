Name: safeguard
Version: 1.0.0
Release: 1%{?dist}
Summary: A tool for restricting network, file, mount and process operations using eBPF
License: MIT
Source0: https://git.culinux.net:8089/CULinux/safeguard/archive/v%{version}.tar.gz
# Source0: /root/rpmbuild/SOURCES/%{name}-v%{version}.tar.gz

BuildRequires: gcc, clang, llvm, elfutils-libelf-devel, zlib-devel
Requires: bpftool

%description
Safeguard is a tool for restricting network, file, mount and process operations using eBPF. It can be used to implement security policies for containers or processes.

%prep
%setup -q -n safeguard

%build
make libbpf-static && make build

%install
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/etc/safeguard
cp -a build/safeguard %{buildroot}/usr/bin/
cp -a config/safeguard.yml %{buildroot}/etc/safeguard/

%check
make test/unit

%files
%license LICENSE
%doc README.md
/usr/bin/safeguard
/etc/safeguard/safeguard.yml

%changelog
* Wed Aug 09 2023 Tong <...> - 1.0.0-1
- Initial package