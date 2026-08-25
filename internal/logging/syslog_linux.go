//go:build linux

package logging

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ipulse/ipulse/internal/events"
	"github.com/ipulse/ipulse/internal/version"
)

// journaldSocket is the native journald datagram socket. Writing to it directly means
// iPulse integrates with journald without cgo, without libsystemd and without shelling
// out to logger(1).
const journaldSocket = "/run/systemd/journal/socket"

// syslogSink forwards significant events to journald when available, and otherwise to
// the classic /dev/log syslog socket in RFC 3164 form.
type syslogSink struct {
	mu       sync.Mutex
	conn     net.Conn
	journald bool
	minSev   events.Severity
	tag      string
	hostname string
	pid      int
}

// newSyslogSink connects to the platform log. A failure to connect is not fatal: the
// file and database sinks still record everything.
func newSyslogSink(minSev events.Severity) (Sink, error) {
	host, _ := os.Hostname()
	s := &syslogSink{minSev: minSev, tag: version.LinuxServiceName, hostname: host, pid: os.Getpid()}

	if _, err := os.Stat(journaldSocket); err == nil {
		if c, err := net.Dial("unixgram", journaldSocket); err == nil {
			s.conn, s.journald = c, true
			return s, nil
		}
	}
	for _, path := range []string{"/dev/log", "/var/run/syslog"} {
		for _, netw := range []string{"unixgram", "unix"} {
			if c, err := net.Dial(netw, path); err == nil {
				s.conn = c
				return s, nil
			}
		}
	}
	return nil, fmt.Errorf("logging: no journald or syslog socket available")
}

func (s *syslogSink) Name() string {
	if s.journald {
		return "journald"
	}
	return "syslog"
}

func (s *syslogSink) Write(ev events.Event) error {
	if ev.Severity < s.minSev {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return nil
	}
	if s.journald {
		_, err := s.conn.Write(s.journalRecord(ev))
		return err
	}
	// RFC 3164: <priority>timestamp hostname tag[pid]: message
	// Facility 16 (local0) keeps agent output out of the system facilities.
	pri := 16*8 + ev.Severity.Syslog()
	msg := fmt.Sprintf("<%d>%s %s %s[%d]: %s\n",
		pri, ev.Time.Format(time.Stamp), s.hostname, s.tag, s.pid, ev.OneLine())
	_, err := s.conn.Write([]byte(msg))
	return err
}

// journalRecord builds the journald native protocol payload. Simple values are written
// as KEY=value lines; values containing a newline use the length-prefixed binary form.
func (s *syslogSink) journalRecord(ev events.Event) []byte {
	var b strings.Builder
	add := func(k, v string) {
		if v == "" {
			return
		}
		if strings.ContainsRune(v, '\n') {
			b.WriteString(k)
			b.WriteByte('\n')
			var le [8]byte
			n := uint64(len(v))
			for i := 0; i < 8; i++ {
				le[i] = byte(n >> (8 * uint(i)))
			}
			b.Write(le[:])
			b.WriteString(v)
			b.WriteByte('\n')
			return
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(v)
		b.WriteByte('\n')
	}
	add("MESSAGE", ev.OneLine())
	add("PRIORITY", fmt.Sprint(ev.Severity.Syslog()))
	add("SYSLOG_IDENTIFIER", s.tag)
	add("SYSLOG_FACILITY", "16")
	add("IPULSE_EVENT_ID", fmt.Sprint(ev.Code))
	add("IPULSE_EVENT", ev.Name)
	add("IPULSE_CATEGORY", string(ev.Category))
	add("IPULSE_SEVERITY", ev.Severity.String())
	if ev.Process != "" {
		add("IPULSE_PROCESS", ev.Process)
	}
	if ev.Destination != "" {
		add("IPULSE_DESTINATION", ev.Destination)
	}
	for _, f := range ev.Fields {
		add("IPULSE_"+strings.ToUpper(f.Key), f.Value)
	}
	return []byte(b.String())
}

func (s *syslogSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return nil
	}
	err := s.conn.Close()
	s.conn = nil
	return err
}
