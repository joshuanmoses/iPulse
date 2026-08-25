package agent

import (
	"runtime"
	"strconv"
	"time"

	"github.com/ipulse/ipulse/internal/anomaly"
)

// gate is the agent's alias for the detection gate, constructed from the live alert
// configuration so a reload changes detector behaviour without a restart.
type gate = anomaly.Gate

// newGate builds a gate using the configured persistence and cooldown.
func (a *Agent) newGate() *gate {
	return anomaly.NewGate(a.cfg.Alerts.Persistence, a.cfg.Alerts.RecoveryPersistence,
		a.cfg.Alerts.Cooldown.D())
}

// once runs fn the first time the key is seen, and then at most once per 24 hours so a
// long-running agent still re-states persistent limitations in a day's worth of logs.
func (a *Agent) once(key string, fn func()) {
	a.onceMu.Lock()
	if a.onceSeen == nil {
		a.onceSeen = map[string]time.Time{}
	}
	last, seen := a.onceSeen[key]
	now := time.Now()
	if seen && now.Sub(last) < 24*time.Hour {
		a.onceMu.Unlock()
		return
	}
	a.onceSeen[key] = now
	a.onceMu.Unlock()
	fn()
}

// itoa and formatFloat1 keep small numeric renderings local to the agent, avoiding a
// dependency on fmt in hot paths that run every cycle.
func itoa(v int64) string { return strconv.FormatInt(v, 10) }

func formatFloat1(v float64) string { return strconv.FormatFloat(v, 'f', 1, 64) }

// runtimeGOOS is wrapped so the remedy text can be tested without build tags.
func runtimeGOOS() string { return runtime.GOOS }
