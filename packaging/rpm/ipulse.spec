# iPulse RPM specification.
#
# The binary is built separately (scripts/build.sh --all) and the spec packages the
# artifact, because iPulse cross-compiles cleanly and rebuilding inside rpmbuild would
# require a Go toolchain on every build host.

%global debug_package %{nil}
%global __strip /bin/true

Name:           ipulse
Version:        %{?_version}%{!?_version:1.0.0}
Release:        1%{?dist}
Summary:        Internet connection monitoring and network observability agent

License:        MIT
URL:            https://github.com/ipulse/ipulse
Source0:        ipulse
Source1:        ipulse.yaml
Source2:        ipulse.service
Source3:        README.md
Source4:        LICENSE
Source5:        CHANGELOG.md
Source6:        docs.tar.gz

BuildRequires:  systemd-rpm-macros
Requires(pre):  shadow-utils
%{?systemd_requires}

%description
iPulse continuously measures Internet availability, connection quality and speed, and
analyses local and external network activity to identify performance problems, outages,
unusual traffic behaviour and suspicious connections.

Everything is stored locally in SQLite. There is no cloud account, no telemetry and no
payload capture: iPulse collects metadata only, and performs no TLS interception.

The service runs as an unprivileged account with two capabilities: CAP_NET_RAW for ICMP
and path measurement, and CAP_DAC_READ_SEARCH so connections can be attributed to the
processes that own them.

%prep
# Nothing to unpack: the sources are the built artifacts.

%build
# Nothing to build: see the note at the top of this file.

%install
install -D -m 0755 %{SOURCE0} %{buildroot}%{_bindir}/ipulse
install -D -m 0640 %{SOURCE1} %{buildroot}%{_sysconfdir}/ipulse/ipulse.yaml
install -D -m 0644 %{SOURCE2} %{buildroot}%{_unitdir}/ipulse.service
install -d -m 0750 %{buildroot}%{_sharedstatedir}/ipulse
install -d -m 0750 %{buildroot}%{_localstatedir}/log/ipulse

# Documentation is installed from the sources rather than through %%doc, so the package
# can be built from artifacts without a populated build directory.
install -D -m 0644 %{SOURCE3} %{buildroot}%{_datadir}/doc/ipulse/README.md
install -D -m 0644 %{SOURCE4} %{buildroot}%{_datadir}/licenses/ipulse/LICENSE
install -D -m 0644 %{SOURCE5} %{buildroot}%{_datadir}/doc/ipulse/CHANGELOG.md
install -d -m 0755 %{buildroot}%{_datadir}/doc/ipulse/docs
tar xzf %{SOURCE6} -C %{buildroot}%{_datadir}/doc/ipulse/docs

%pre
# A dedicated unprivileged account owns the agent's files and its process.
getent group ipulse >/dev/null || groupadd --system ipulse
getent passwd ipulse >/dev/null || \
    useradd --system --gid ipulse --home-dir %{_sharedstatedir}/ipulse \
            --no-create-home --shell /sbin/nologin \
            --comment "iPulse monitoring agent" ipulse
exit 0

%post
%systemd_post ipulse.service
if [ $1 -eq 1 ]; then
    # First install: validate before enabling, so a typo does not produce a service
    # that fails at every boot.
    if %{_bindir}/ipulse config validate --config %{_sysconfdir}/ipulse/ipulse.yaml >/dev/null 2>&1; then
        systemctl enable --now ipulse.service >/dev/null 2>&1 || :
        echo "iPulse is running. Dashboard: http://127.0.0.1:8750"
        echo "Set your ISP plan in %{_sysconfdir}/ipulse/ipulse.yaml (speed_test.expected_*_mbps)."
    else
        echo "iPulse: the configuration is not valid; the service was not started." >&2
        echo "iPulse: run 'ipulse config validate' to see the problems." >&2
    fi
fi

%preun
%systemd_preun ipulse.service

%postun
%systemd_postun_with_restart ipulse.service
# Measurements survive an upgrade and an ordinary removal. Only an explicit cleanup
# removes them, which is left to the administrator.
if [ $1 -eq 0 ]; then
    echo "iPulse removed. Historical data kept in %{_sharedstatedir}/ipulse and %{_localstatedir}/log/ipulse."
    echo "Remove them by hand if they are no longer wanted."
fi

%files
%license %{_datadir}/licenses/ipulse/LICENSE
%doc %{_datadir}/doc/ipulse/README.md
%doc %{_datadir}/doc/ipulse/CHANGELOG.md
%doc %{_datadir}/doc/ipulse/docs
%{_bindir}/ipulse
%{_unitdir}/ipulse.service
%dir %attr(0750, root, ipulse) %{_sysconfdir}/ipulse
%config(noreplace) %attr(0640, root, ipulse) %{_sysconfdir}/ipulse/ipulse.yaml
%dir %attr(0750, ipulse, ipulse) %{_sharedstatedir}/ipulse
%dir %attr(0750, ipulse, ipulse) %{_localstatedir}/log/ipulse

%changelog
* Mon Aug 24 2026 iPulse Authors <ipulse@example.invalid> - 1.0.0-1
- Initial release.
