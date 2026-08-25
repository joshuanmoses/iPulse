//go:build linux

package linux

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/ipulse/ipulse/internal/platform/types"
)

// tcpStates maps the kernel's numeric TCP states onto the normalised names.
var tcpStates = map[uint64]string{
	0x01: types.StateEstablished,
	0x02: types.StateSynSent,
	0x03: types.StateSynRecv,
	0x04: types.StateFinWait1,
	0x05: types.StateFinWait2,
	0x06: types.StateTimeWait,
	0x07: types.StateClosed,
	0x08: types.StateCloseWait,
	0x09: types.StateLastAck,
	0x0A: types.StateListen,
	0x0B: types.StateClosing,
}

// Connections reads the socket tables from /proc/net and, when requested, attributes
// each socket to a process by mapping its inode through /proc/<pid>/fd.
func (p *Provider) Connections(opts types.ConnOptions) ([]types.Connection, error) {
	if !opts.TCP && !opts.UDP {
		opts.TCP = true
	}
	var conns []types.Connection

	type src struct {
		path  string
		proto string
		v6    bool
	}
	var sources []src
	if opts.TCP {
		sources = append(sources, src{procNetTCP, "tcp", false}, src{procNetTCP6, "tcp", true})
	}
	if opts.UDP {
		sources = append(sources, src{procNetUDP, "udp", false}, src{procNetUDP6, "udp", true})
	}

	var firstErr error
	for _, s := range sources {
		got, err := readProcNet(s.path, s.proto, s.v6, opts)
		if err != nil {
			// A missing tcp6 file simply means IPv6 is disabled; that is not an error
			// worth failing the whole collection for.
			if firstErr == nil && !os.IsNotExist(err) {
				firstErr = err
			}
			continue
		}
		conns = append(conns, got...)
	}
	if len(conns) == 0 && firstErr != nil {
		return nil, firstErr
	}

	if opts.ResolveProcess {
		attributeProcesses(conns)
	}
	if opts.Max > 0 && len(conns) > opts.Max {
		conns = conns[:opts.Max]
	}
	return conns, nil
}

func readProcNet(path, proto string, v6 bool, opts types.ConnOptions) ([]types.Connection, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []types.Connection
	sc := bufio.NewScanner(f)
	buf := make([]byte, 0, 256*1024)
	sc.Buffer(buf, 1024*1024)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		// sl local rem st tx:rx tr:when retrnsmt uid timeout inode ...
		if len(fields) < 10 {
			continue
		}
		local, ok := parseProcAddr(fields[1], v6)
		if !ok {
			continue
		}
		remote, ok := parseProcAddr(fields[2], v6)
		if !ok {
			continue
		}
		stateNum, err := strconv.ParseUint(fields[3], 16, 8)
		if err != nil {
			continue
		}
		state := types.StateNone
		if proto == "tcp" {
			state = tcpStates[stateNum]
			if state == "" {
				state = types.StateNone
			}
		}
		if state == types.StateListen && !opts.IncludeListening {
			continue
		}
		if !opts.IncludeLoopback && (local.Addr().IsLoopback() || remote.Addr().IsLoopback()) {
			continue
		}
		// A UDP socket with no peer is a listener, not a conversation.
		if proto == "udp" && (remote.Addr().IsUnspecified() || remote.Port() == 0) && !opts.IncludeListening {
			continue
		}

		var txq, rxq uint64
		if qs := strings.SplitN(fields[4], ":", 2); len(qs) == 2 {
			txq, _ = strconv.ParseUint(qs[0], 16, 64)
			rxq, _ = strconv.ParseUint(qs[1], 16, 64)
		}
		inode, _ := strconv.ParseUint(fields[9], 10, 64)

		c := types.Connection{
			Protocol: proto,
			Local:    local,
			Remote:   remote,
			State:    state,
			Inode:    inode,
			TxQueue:  txq,
			RxQueue:  rxq,
		}
		if uid, err := strconv.Atoi(fields[7]); err == nil {
			c.User = lookupUser(uid)
		}
		out = append(out, c)
	}
	return out, sc.Err()
}

// parseProcAddr decodes the "HEXADDR:HEXPORT" form used throughout /proc/net. IPv4 is a
// single little-endian word; IPv6 is four little-endian words.
func parseProcAddr(s string, v6 bool) (netip.AddrPort, bool) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return netip.AddrPort{}, false
	}
	hostHex, portHex := s[:i], s[i+1:]
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return netip.AddrPort{}, false
	}
	if v6 {
		if len(hostHex) != 32 {
			return netip.AddrPort{}, false
		}
		raw, err := hex.DecodeString(hostHex)
		if err != nil {
			return netip.AddrPort{}, false
		}
		var b [16]byte
		for w := 0; w < 4; w++ {
			word := binary.LittleEndian.Uint32(raw[w*4 : w*4+4])
			binary.BigEndian.PutUint32(b[w*4:w*4+4], word)
		}
		return netip.AddrPortFrom(netip.AddrFrom16(b).Unmap(), uint16(port)), true
	}
	v, err := strconv.ParseUint(hostHex, 16, 32)
	if err != nil {
		return netip.AddrPort{}, false
	}
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(v))
	return netip.AddrPortFrom(netip.AddrFrom4(b), uint16(port)), true
}

// attributeProcesses maps socket inodes to owning processes. The scan over /proc is the
// only way Linux exposes this relationship, so it is done once per collection cycle and
// only for the inodes actually present.
func attributeProcesses(conns []types.Connection) {
	wanted := make(map[uint64]int, len(conns))
	for i := range conns {
		if conns[i].Inode != 0 {
			wanted[conns[i].Inode] = -1
		}
	}
	if len(wanted) == 0 {
		return
	}

	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, ok := atoiSafe(e.Name())
		if !ok {
			continue
		}
		fdDir := procRoot + "/" + e.Name() + "/fd"
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue // process exited, or not permitted: skip quietly
		}
		for _, fd := range fds {
			link, err := os.Readlink(fdDir + "/" + fd.Name())
			if err != nil {
				continue
			}
			// Links look like "socket:[12345]".
			if !strings.HasPrefix(link, "socket:[") || !strings.HasSuffix(link, "]") {
				continue
			}
			inode, ok := atoiSafe(link[8 : len(link)-1])
			if !ok {
				continue
			}
			if _, want := wanted[uint64(inode)]; want {
				wanted[uint64(inode)] = pid
			}
		}
	}

	cache := map[int]types.Process{}
	for i := range conns {
		pid, ok := wanted[conns[i].Inode]
		if !ok || pid <= 0 {
			continue
		}
		proc, cached := cache[pid]
		if !cached {
			proc, _ = processInfo(pid)
			cache[pid] = proc
		}
		conns[i].PID = pid
		conns[i].Process = proc.Name
		conns[i].Exe = proc.Exe
		if proc.User != "" {
			conns[i].User = proc.User
		}
	}
}

// ProcessInfo looks up one process by pid.
func (p *Provider) ProcessInfo(pid int) (types.Process, error) { return processInfo(pid) }

func processInfo(pid int) (types.Process, error) {
	base := fmt.Sprintf("%s/%d", procRoot, pid)
	proc := types.Process{PID: pid}

	if b, err := os.ReadFile(base + "/comm"); err == nil {
		proc.Name = strings.TrimSpace(string(b))
	} else if os.IsNotExist(err) {
		return proc, types.ErrNotFound
	}
	// The exe link needs the same privileges as the fd directory; a failure here is
	// expected for other users' processes and is not an error.
	if exe, err := os.Readlink(base + "/exe"); err == nil {
		proc.Exe = exe
		if proc.Name == "" {
			proc.Name = exe[strings.LastIndexByte(exe, '/')+1:]
		}
	}
	if b, err := os.ReadFile(base + "/status"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "Uid:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					if uid, err := strconv.Atoi(fields[1]); err == nil {
						proc.User = lookupUser(uid)
					}
				}
				break
			}
		}
	}
	if proc.Name == "" {
		return proc, types.ErrNotFound
	}
	return proc, nil
}

// userCache avoids re-reading /etc/passwd for every socket. iPulse deliberately parses
// the file itself rather than calling into libc's NSS, which would require cgo.
var (
	userOnce  sync.Once
	userNames map[int]string
	userMu    sync.RWMutex
)

func lookupUser(uid int) string {
	userOnce.Do(func() {
		userNames = map[int]string{}
		loadPasswd()
	})
	userMu.RLock()
	name, ok := userNames[uid]
	userMu.RUnlock()
	if ok {
		return name
	}
	return strconv.Itoa(uid)
}

func loadPasswd() {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	userMu.Lock()
	defer userMu.Unlock()
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 3 {
			continue
		}
		if uid, err := strconv.Atoi(parts[2]); err == nil {
			userNames[uid] = parts[0]
		}
	}
}
