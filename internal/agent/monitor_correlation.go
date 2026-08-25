package agent

import (
	"context"
	"fmt"
	"time"

	"github.com/ipulse/ipulse/internal/correlation"
	"github.com/ipulse/ipulse/internal/events"
)

// correlationMonitor turns groups of related signals into a single conclusion.
//
// It consumes two streams: every event the logger publishes (with its database id, so
// contributing events can be marked as absorbed) and every sample collectors publish.
// Evaluation runs on a short interval rather than on every signal, because a conclusion
// should be drawn once the symptoms have had a moment to arrive together.
//
// On suppression: iPulse marks the contributing events as absorbed in the database, so
// the dashboard, the API and `ipulse events` show the conclusion rather than the list of
// symptoms. The flat log files are append-only and keep the raw records, which is the
// right trade: an operator tailing a file sees everything as it happens, and anyone
// reviewing history sees the explanation.
type correlationMonitor struct {
	a      *Agent
	engine *correlation.Engine
	events <-chan events.Event
}

func newCorrelationMonitor(a *Agent) *correlationMonitor {
	return &correlationMonitor{
		a:      a,
		engine: correlation.NewEngine(a.cfg.Correlation.Window.D(), correlation.DefaultRules()),
		// A generous buffer: the drain runs every few seconds, and dropping a symptom
		// would weaken a conclusion.
		events: a.log.Subscribe(2048),
	}
}

func (m *correlationMonitor) Name() string { return "correlation" }

func (m *correlationMonitor) Tasks() []Task {
	return []Task{{
		Name:       "correlation",
		Interval:   5 * time.Second,
		Timeout:    15 * time.Second,
		RunOnStart: false,
		Fn:         m.run,
	}}
}

// Samples implements sampleConsumer: measurements feed the same window as events.
func (m *correlationMonitor) Samples(ctx context.Context, batch []sample) {
	for _, s := range batch {
		if !s.Valid {
			continue
		}
		m.engine.Observe(correlation.Signal{
			Time:   s.Time,
			Kind:   correlation.KindSample,
			Name:   s.Metric,
			Value:  s.Value,
			Target: s.Target,
		})
	}
}

func (m *correlationMonitor) run(ctx context.Context) error {
	m.engine.SetEnabled(m.a.cfg.Correlation.Enabled)
	m.drainEvents()

	match, ok := m.engine.Evaluate(time.Now())
	if !ok {
		return nil
	}

	correlationID := fmt.Sprintf("%s-%d", match.Rule.Name, match.Time.UnixMilli())
	ev := events.New(match.Rule.Conclusion).
		WithFields(match.Fields).
		WithField("ProbableCause", match.Cause).
		WithField("Evidence", match.EvidenceString()).
		WithField("Rule", match.Rule.Name).
		WithField("Window", m.engine.WindowSize()).
		WithCorrelation(correlationID)
	m.a.log.Emit(ev)

	if m.a.cfg.Correlation.SuppressContributing && len(match.SuppressID) > 0 {
		if err := m.a.db.MarkSuppressed(ctx, match.SuppressID, correlationID); err != nil {
			return err
		}
	}
	return nil
}

// drainEvents moves everything the logger has published into the correlation window.
func (m *correlationMonitor) drainEvents() {
	for {
		select {
		case ev, ok := <-m.events:
			if !ok {
				return
			}
			m.engine.Observe(correlation.Signal{
				Time:    ev.Time,
				Kind:    correlation.KindEvent,
				Name:    ev.Name,
				Code:    ev.Code,
				Fields:  ev.Fields.Map(),
				EventID: ev.ID,
			})
		default:
			return
		}
	}
}
