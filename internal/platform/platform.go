// Package platform is the operating-system abstraction boundary.
//
// Every OS-specific mechanism iPulse uses lives behind the Provider interface declared
// here. The Linux implementation (internal/platform/linux) reads /proc and /sys and
// issues ioctls; the Windows implementation (internal/platform/windows) calls iphlpapi
// and wlanapi. Nothing outside those two packages knows which platform it runs on.
//
// The data types live in internal/platform/types, which lets the implementations and
// this facade share them without an import cycle; they are re-exported here as aliases
// so callers only ever import internal/platform.
//
// Operations that are unavailable (unsupported platform, or insufficient privilege)
// return ErrUnsupported or ErrPermission, so callers degrade gracefully and report the
// limitation once rather than on every cycle.
package platform

import (
	"net/netip"

	"github.com/ipulse/ipulse/internal/platform/types"
)

// Re-exported data types. See internal/platform/types for the definitions.
type (
	Counters     = types.Counters
	Interface    = types.Interface
	Route        = types.Route
	Connection   = types.Connection
	ConnOptions  = types.ConnOptions
	WirelessLink = types.WirelessLink
	Process      = types.Process
	Capabilities = types.Capabilities
)

// Re-exported sentinel errors.
var (
	ErrUnsupported = types.ErrUnsupported
	ErrPermission  = types.ErrPermission
	ErrNotFound    = types.ErrNotFound
)

// Re-exported interface types.
const (
	IfaceEthernet = types.IfaceEthernet
	IfaceWireless = types.IfaceWireless
	IfaceLoopback = types.IfaceLoopback
	IfaceTunnel   = types.IfaceTunnel
	IfaceVirtual  = types.IfaceVirtual
	IfaceOther    = types.IfaceOther
)

// Re-exported connection states.
const (
	StateEstablished = types.StateEstablished
	StateSynSent     = types.StateSynSent
	StateSynRecv     = types.StateSynRecv
	StateListen      = types.StateListen
	StateTimeWait    = types.StateTimeWait
	StateCloseWait   = types.StateCloseWait
	StateClosed      = types.StateClosed
	StateClosing     = types.StateClosing
	StateFinWait1    = types.StateFinWait1
	StateFinWait2    = types.StateFinWait2
	StateLastAck     = types.StateLastAck
	StateDeleteTCB   = types.StateDeleteTCB
	StateNone        = types.StateNone
)

// Re-exported helpers.
var (
	DefaultRoute        = types.DefaultRoute
	DefaultRouteFor     = types.DefaultRouteFor
	ClassifyInterface   = types.ClassifyInterface
	IsTunnel            = types.IsTunnel
	SignalPercent       = types.SignalPercent
	ChannelForFrequency = types.ChannelForFrequency
	BandForFrequency    = types.BandForFrequency
	ConnectionKey       = types.ConnectionKey
)

// Provider is the platform abstraction. One implementation is compiled in per OS.
type Provider interface {
	// Name identifies the implementation, for example "linux" or "windows".
	Name() string
	// Capabilities probes what this process can actually do. It is called once at
	// start-up and is cheap enough to call again after a privilege change.
	Capabilities() Capabilities

	// Interfaces returns every interface with its counters and addresses.
	Interfaces() ([]Interface, error)
	// Routes returns the routing table, including default routes.
	Routes() ([]Route, error)
	// Connections returns active sockets, with process attribution when requested and
	// permitted.
	Connections(opts ConnOptions) ([]Connection, error)
	// Wireless returns telemetry for associated wireless interfaces.
	Wireless() ([]WirelessLink, error)
	// DNSServers returns the resolvers the system is configured to use.
	DNSServers() ([]netip.AddrPort, error)
	// ProcessInfo looks up one process.
	ProcessInfo(pid int) (Process, error)
}

// New returns the provider for the current platform.
func New() Provider { return newProvider() }
