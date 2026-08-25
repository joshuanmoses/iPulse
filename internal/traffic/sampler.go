package traffic

import (
	"math"
	"time"

	"github.com/ipulse/ipulse/internal/platform"
	"github.com/ipulse/ipulse/internal/util"
)

// Sample is one interface's throughput over the interval since the previous sample.
type Sample struct {
	Time      time.Time
	Interface string
	Type      string
	Interval  time.Duration

	// Absolute counters, as read.
	RxBytes   uint64
	TxBytes   uint64
	RxPackets uint64
	TxPackets uint64
	RxErrors  uint64
	TxErrors  uint64
	RxDropped uint64
	TxDropped uint64

	// Deltas over the interval.
	RxDelta      int64
	TxDelta      int64
	ErrorsDelta  int64
	DroppedDelta int64

	// Rates in bits per second, with iPulse's own traffic removed.
	RxBps float64
	TxBps float64
	// SelfRxBps and SelfTxBps are the portion attributable to iPulse.
	SelfRxBps float64
	SelfTxBps float64
	// SelfActive reports that iPulse was transferring during this interval, so a
	// detector can skip it entirely rather than trusting the subtraction.
	SelfActive bool

	// Reset is true when the counters went backwards (interface reset or counter wrap),
	// in which case the rates are not meaningful and the sample is not usable.
	Reset bool
}

// Usable reports whether the sample can be used for rate analysis.
func (s Sample) Usable() bool { return !s.Reset && s.Interval > 0 }

// TotalBps is the combined rate, used for the "is the link busy" check.
func (s Sample) TotalBps() float64 { return s.RxBps + s.TxBps }

// Config configures the sampler.
type Config struct {
	// Include limits sampling to these interface names (globs). Empty means all.
	Include []string
	// Exclude skips these interface names (globs).
	Exclude []string
	// ExcludeSelf subtracts iPulse's own transfers from the reported rates.
	ExcludeSelf bool
}

// Sampler turns successive interface counter readings into rates.
//
// Two details make this correct rather than approximately correct. Counters that go
// backwards (an interface reset, a driver reload, or a 32-bit counter wrapping) are
// reported as a reset instead of producing an absurd spike. And the elapsed time is
// measured per interface from its own previous reading, so a skipped cycle does not
// inflate the rate.
type Sampler struct {
	cfg  Config
	self *SelfTraffic
	prev map[string]Sample
}

// NewSampler creates a sampler. self may be nil.
func NewSampler(cfg Config, self *SelfTraffic) *Sampler {
	return &Sampler{cfg: cfg, self: self, prev: map[string]Sample{}}
}

// Sample reads the interfaces and returns one sample per monitored interface. The first
// call establishes the baseline and returns nothing, because a rate needs two readings.
func (s *Sampler) Sample(ifaces []platform.Interface, now time.Time) []Sample {
	out := make([]Sample, 0, len(ifaces))
	seen := make(map[string]bool, len(ifaces))

	for _, iface := range ifaces {
		if !s.monitored(iface) {
			continue
		}
		seen[iface.Name] = true

		cur := Sample{
			Time:      now,
			Interface: iface.Name,
			Type:      iface.Type,
			RxBytes:   iface.Counters.RxBytes,
			TxBytes:   iface.Counters.TxBytes,
			RxPackets: iface.Counters.RxPackets,
			TxPackets: iface.Counters.TxPackets,
			RxErrors:  iface.Counters.RxErrors,
			TxErrors:  iface.Counters.TxErrors,
			RxDropped: iface.Counters.RxDropped,
			TxDropped: iface.Counters.TxDropped,
		}

		prev, had := s.prev[iface.Name]
		s.prev[iface.Name] = cur
		if !had {
			continue // first reading for this interface
		}

		cur.Interval = now.Sub(prev.Time)
		if cur.Interval <= 0 {
			continue
		}
		// A counter that went backwards means the interface or the counter was reset.
		if cur.RxBytes < prev.RxBytes || cur.TxBytes < prev.TxBytes {
			cur.Reset = true
			out = append(out, cur)
			continue
		}

		cur.RxDelta = int64(cur.RxBytes - prev.RxBytes)
		cur.TxDelta = int64(cur.TxBytes - prev.TxBytes)
		cur.ErrorsDelta = int64(cur.RxErrors+cur.TxErrors) - int64(prev.RxErrors+prev.TxErrors)
		cur.DroppedDelta = int64(cur.RxDropped+cur.TxDropped) - int64(prev.RxDropped+prev.TxDropped)

		seconds := cur.Interval.Seconds()
		rxBits := float64(cur.RxDelta) * 8
		txBits := float64(cur.TxDelta) * 8

		if s.cfg.ExcludeSelf && s.self != nil {
			selfRx, selfTx := s.self.Between(prev.Time, now)
			cur.SelfRxBps = float64(selfRx) * 8 / seconds
			cur.SelfTxBps = float64(selfTx) * 8 / seconds
			cur.SelfActive = s.self.Active(prev.Time, now)
			// Subtract, but never below zero: attribution is proportional, so a small
			// overshoot is possible and a negative rate would be nonsense.
			rxBits = math.Max(0, rxBits-float64(selfRx)*8)
			txBits = math.Max(0, txBits-float64(selfTx)*8)
		}

		cur.RxBps = rxBits / seconds
		cur.TxBps = txBits / seconds
		out = append(out, cur)
	}

	// Forget interfaces that have disappeared, so a container host does not accumulate
	// state for every short-lived veth device.
	for name := range s.prev {
		if !seen[name] {
			delete(s.prev, name)
		}
	}
	return out
}

// monitored applies the include and exclude patterns.
func (s *Sampler) monitored(iface platform.Interface) bool {
	// Loopback carries no Internet traffic, and virtual devices double-count what the
	// real interface already reported.
	if iface.IsLoopback() {
		return false
	}
	if len(s.cfg.Include) > 0 {
		return util.MatchesAnyGlob(s.cfg.Include, iface.Name)
	}
	if util.MatchesAnyGlob(s.cfg.Exclude, iface.Name) {
		return false
	}
	return true
}

// Primary returns the sample for the named interface, which is how the agent finds the
// throughput of the interface currently carrying the default route.
func Primary(samples []Sample, name string) (Sample, bool) {
	for _, s := range samples {
		if s.Interface == name {
			return s, true
		}
	}
	return Sample{}, false
}

// Busiest returns the sample with the highest combined rate.
func Busiest(samples []Sample) (Sample, bool) {
	var best Sample
	found := false
	for _, s := range samples {
		if !s.Usable() {
			continue
		}
		if !found || s.TotalBps() > best.TotalBps() {
			best, found = s, true
		}
	}
	return best, found
}

// Tracked returns the interfaces the sampler currently has state for.
func (s *Sampler) Tracked() int { return len(s.prev) }
