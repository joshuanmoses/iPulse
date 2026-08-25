package agent

import (
	"context"
	"time"
)

// sample is one numeric observation published to the analysis pipeline.
//
// Collectors publish samples; the analysis pipeline (baselines, anomaly detectors,
// correlation) consumes them on a single goroutine. That single-consumer design is what
// makes detection deterministic: for a given sequence of samples, the emitted events are
// fully determined, which is exactly what the simulation tests rely on.
type sample struct {
	Time   time.Time
	Metric string
	// Target is the dimension: a probe target, an interface, a process or empty for
	// the connection as a whole.
	Target string
	Value  float64
	// Valid is false for a failed measurement, which must not pollute a baseline.
	Valid bool
}

// sampleConsumer receives batches of samples.
type sampleConsumer interface {
	// Samples is called from the analysis goroutine, so implementations need no
	// internal locking for their own state.
	Samples(ctx context.Context, batch []sample)
}

// sampleQueueDepth bounds the in-flight sample queue. Overflow drops the oldest batch:
// analysis falling behind must never slow down measurement.
const sampleQueueDepth = 512

// publishSamples sends a batch to the analysis pipeline. Samples with Valid false are
// forwarded too, because "this probe failed" is itself information a detector uses.
func (a *Agent) publishSamples(now time.Time, ss ...sample) {
	if len(a.consumers) == 0 || len(ss) == 0 {
		return
	}
	batch := make([]sample, 0, len(ss))
	for _, s := range ss {
		if s.Time.IsZero() {
			s.Time = now
		}
		batch = append(batch, s)
	}
	select {
	case a.samples <- batch:
	default:
		a.samplesDropped.Add(1)
	}
}

// runAnalysis is the single analysis goroutine.
func (a *Agent) runAnalysis(ctx context.Context) {
	defer close(a.analysisDone)
	for {
		select {
		case <-ctx.Done():
			// Drain what is queued so a shutdown does not lose the final samples.
			for {
				select {
				case batch := <-a.samples:
					a.dispatch(ctx, batch)
				default:
					return
				}
			}
		case batch := <-a.samples:
			a.dispatch(ctx, batch)
		}
	}
}

func (a *Agent) dispatch(ctx context.Context, batch []sample) {
	for _, c := range a.consumers {
		func() {
			// A panic in a detector must not stop analysis for everything else.
			defer a.recoverPanic("analysis")
			c.Samples(ctx, batch)
		}()
	}
}
