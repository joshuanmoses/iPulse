package service

import (
	"fmt"
	"strings"

	"github.com/ipulse/ipulse/internal/version"
)

// renderUnit produces a hardened systemd unit.
//
// The hardening directives are not decoration: iPulse runs continuously as a service,
// so it is given the narrowest capability set that still lets it measure the network
// (CAP_NET_RAW for ICMP, CAP_DAC_READ_SEARCH for socket-to-process attribution) and is
// otherwise confined away from the rest of the system.
func renderUnitPortable(exe string, opts InstallOptions) (string, error) {
	quotedExe, err := quoteArg(exe)
	if err != nil {
		return "", err
	}
	args := quotedExe + " service run"
	if opts.ConfigPath != "" {
		q, err := quoteArg(opts.ConfigPath)
		if err != nil {
			return "", err
		}
		args += " --config " + q
	}
	user := opts.User
	if user == "" {
		user = version.LinuxServiceName
	}
	group := opts.Group
	if group == "" {
		group = user
	}
	dataDir := opts.DataDir
	if dataDir == "" {
		dataDir = "/var/lib/ipulse"
	}
	logDir := opts.LogDir
	if logDir == "" {
		logDir = "/var/log/ipulse"
	}

	var b strings.Builder
	b.WriteString("[Unit]\n")
	fmt.Fprintf(&b, "Description=%s\n", version.Description)
	b.WriteString("Documentation=https://github.com/ipulse/ipulse/tree/main/docs\n")
	b.WriteString("After=network-online.target\n")
	b.WriteString("Wants=network-online.target\n")
	b.WriteString("\n[Service]\n")
	b.WriteString("Type=notify\n")
	b.WriteString("NotifyAccess=main\n")
	fmt.Fprintf(&b, "ExecStart=%s\n", args)
	fmt.Fprintf(&b, "ExecReload=/bin/kill -HUP $MAINPID\n")
	fmt.Fprintf(&b, "User=%s\nGroup=%s\n", user, group)
	b.WriteString("Restart=on-failure\n")
	b.WriteString("RestartSec=10\n")
	b.WriteString("TimeoutStopSec=30\n")
	b.WriteString("KillMode=mixed\n")
	b.WriteString("WorkingDirectory=" + dataDir + "\n")
	b.WriteString("\n# Least privilege: only what network measurement genuinely needs.\n")
	b.WriteString("AmbientCapabilities=CAP_NET_RAW CAP_DAC_READ_SEARCH\n")
	b.WriteString("CapabilityBoundingSet=CAP_NET_RAW CAP_DAC_READ_SEARCH\n")
	b.WriteString("NoNewPrivileges=true\n")
	b.WriteString("\n# Filesystem confinement.\n")
	b.WriteString("ProtectSystem=strict\n")
	b.WriteString("ProtectHome=true\n")
	b.WriteString("PrivateTmp=true\n")
	b.WriteString("PrivateDevices=true\n")
	fmt.Fprintf(&b, "ReadWritePaths=%s %s\n", dataDir, logDir)
	b.WriteString("StateDirectory=ipulse\n")
	b.WriteString("LogsDirectory=ipulse\n")
	b.WriteString("ConfigurationDirectory=ipulse\n")
	b.WriteString("\n# Kernel and process confinement.\n")
	b.WriteString("ProtectKernelTunables=true\n")
	b.WriteString("ProtectKernelModules=true\n")
	b.WriteString("ProtectKernelLogs=true\n")
	b.WriteString("ProtectControlGroups=true\n")
	b.WriteString("ProtectClock=true\n")
	b.WriteString("ProtectHostname=true\n")
	b.WriteString("RestrictNamespaces=true\n")
	b.WriteString("RestrictRealtime=true\n")
	b.WriteString("RestrictSUIDSGID=true\n")
	b.WriteString("LockPersonality=true\n")
	b.WriteString("MemoryDenyWriteExecute=true\n")
	b.WriteString("SystemCallFilter=@system-service\n")
	b.WriteString("SystemCallErrorNumber=EPERM\n")
	b.WriteString("SystemCallArchitectures=native\n")
	b.WriteString("RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK\n")
	b.WriteString("\n# Resource ceilings appropriate to a monitoring agent.\n")
	b.WriteString("MemoryMax=256M\n")
	b.WriteString("TasksMax=64\n")
	b.WriteString("Nice=5\n")
	b.WriteString("IOSchedulingClass=best-effort\n")
	b.WriteString("IOSchedulingPriority=6\n")
	b.WriteString("\n[Install]\n")
	b.WriteString("WantedBy=multi-user.target\n")
	return b.String(), nil
}
