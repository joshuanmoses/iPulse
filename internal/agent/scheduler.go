// Package agent wires iPulse together: it owns the scheduler, the shared runtime state,
// every collector, the analysis pipeline and the local API.
package agent

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"runtime/debug"
	"sort"
	"sync"
	"time"

	"github.com/ipulse/ipulse/internal/events"
	"github.com/ipulse/ipulse/internal/logging"
)

// Task is one unit of scheduled work.
type Task struct {
	// Name identifies the task in logs and in the API.
	Name string
	// Interval is how often the task runs. Zero means run once at start-up.
	Interval time.Duration
	// Timeout bounds one execution. Zero means Interval, or 30s when Interval is zero.
	Timeout time.Duration
	// Jitter spreads the first run and every subsequent tick, so a host running many
	// probes does not fire them all on the same instant.
	Jitter time.Duration
	// InitialDelay delays the first run. Used to keep heavy probes (a full speed test)
	// away from start-up.
	InitialDelay time.Duration
	// RunOnStart runs the task immediately (after InitialDelay) rather than waiting a
	// whole interval for the first sample.
	RunOnStart bool
	// ManualOnly registers the task without a schedule: it runs only when triggered
	// from the API or the CLI. Used for on-demand diagnostics and tests.
	ManualOnly bool
	// Fn is the work. It must respect ctx.
	Fn func(ctx context.Context) error
}

// TaskStat reports one task's execution history.
type TaskStat struct {
	Name         string        `json:"name"`
	Interval     time.Duration `json:"interval"`
	Runs         int64         `json:"runs"`
	Failures     int64         `json:"failures"`
	Skips        int64         `json:"skips"`
	Running      bool          `json:"running"`
	LastRun      time.Time     `json:"last_run,omitempty"`
	LastDuration time.Duration `json:"last_duration,omitempty"`
	LastError    string        `json:"last_error,omitempty"`
	NextRun      time.Time     `json:"next_run,omitempty"`
}

type taskState struct {
	mu   sync.Mutex
	stat TaskStat
	// manual carries out-of-band run requests from the API and CLI.
	manual chan chan error
}

// Scheduler runs the agent's periodic work. One goroutine per task keeps execution
// serialised per task without any locking in the task itself, and a per-run context
// timeout guarantees that a hung probe can never wedge the agent.
type Scheduler struct {
	log *logging.Logger

	mu     sync.RWMutex
	tasks  []Task
	states map[string]*taskState

	wg      sync.WaitGroup
	started bool
	rnd     *rand.Rand
	rndMu   sync.Mutex
}

// NewScheduler creates a scheduler.
func NewScheduler(log *logging.Logger) *Scheduler {
	return &Scheduler{
		log:    log,
		states: map[string]*taskState{},
		// Deterministic seeding is unnecessary here; jitter only needs to be spread.
		rnd: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Add registers a task. Adding a duplicate name replaces the earlier task, so a
// configuration reload can rebuild the task set without duplicating work.
func (s *Scheduler) Add(t Task) error {
	if t.Name == "" {
		return errors.New("scheduler: task name is required")
	}
	if t.Fn == nil {
		return fmt.Errorf("scheduler: task %q has no function", t.Name)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return fmt.Errorf("scheduler: cannot add task %q after start", t.Name)
	}
	for i, existing := range s.tasks {
		if existing.Name == t.Name {
			s.tasks[i] = t
			return nil
		}
	}
	s.tasks = append(s.tasks, t)
	s.states[t.Name] = &taskState{
		stat:   TaskStat{Name: t.Name, Interval: t.Interval},
		manual: make(chan chan error, 1),
	}
	return nil
}

// Start launches every task. It returns immediately; Wait blocks until they finish.
func (s *Scheduler) Start(ctx context.Context) {
	s.mu.Lock()
	s.started = true
	tasks := make([]Task, len(s.tasks))
	copy(tasks, s.tasks)
	s.mu.Unlock()

	for _, t := range tasks {
		s.wg.Add(1)
		go s.runTask(ctx, t)
	}
}

// Wait blocks until every task goroutine has returned.
func (s *Scheduler) Wait() { s.wg.Wait() }

func (s *Scheduler) jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	s.rndMu.Lock()
	defer s.rndMu.Unlock()
	return time.Duration(s.rnd.Int63n(int64(d)))
}

func (s *Scheduler) runTask(ctx context.Context, t Task) {
	defer s.wg.Done()
	st := s.state(t.Name)

	timeout := t.Timeout
	if timeout <= 0 {
		timeout = t.Interval
		if timeout <= 0 {
			timeout = 30 * time.Second
		}
	}

	if t.ManualOnly {
		// No schedule: serve manual triggers until the agent stops.
		for {
			select {
			case <-ctx.Done():
				return
			case reply := <-st.manual:
				reply <- s.execute(ctx, t, timeout, true)
			}
		}
	}

	delay := t.InitialDelay + s.jitter(t.Jitter)
	if !t.RunOnStart && t.Interval > 0 {
		delay += t.Interval
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	s.setNextRun(st, time.Now().Add(delay))

	for {
		select {
		case <-ctx.Done():
			return
		case reply := <-st.manual:
			// A manual run does not disturb the schedule: the timer keeps its deadline.
			err := s.execute(ctx, t, timeout, true)
			reply <- err
		case <-timer.C:
			_ = s.execute(ctx, t, timeout, false)
			if t.Interval <= 0 {
				return // one-shot task
			}
			next := t.Interval + s.jitter(t.Jitter)
			timer.Reset(next)
			s.setNextRun(st, time.Now().Add(next))
		}
	}
}

// execute runs one iteration with a timeout, panic recovery and statistics.
func (s *Scheduler) execute(ctx context.Context, t Task, timeout time.Duration, manual bool) (err error) {
	st := s.state(t.Name)

	st.mu.Lock()
	if st.stat.Running {
		// Only reachable when a manual run overlaps a scheduled one.
		st.stat.Skips++
		running := st.stat.LastRun
		st.mu.Unlock()
		s.log.Emit(events.New(events.SchedulerTaskSkip).
			WithField("Task", t.Name).
			WithField("Interval", t.Interval).
			WithField("RunningFor", time.Since(running)))
		return errors.New("task is already running")
	}
	st.stat.Running = true
	st.stat.LastRun = time.Now()
	st.mu.Unlock()

	start := time.Now()
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	func() {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("panic: %v", r)
				s.log.Emit(events.New(events.PanicRecovered).
					WithField("Component", "task:"+t.Name).
					WithField("Panic", fmt.Sprint(r)).
					WithField("Stack", string(debug.Stack())))
			}
		}()
		err = t.Fn(runCtx)
	}()
	elapsed := time.Since(start)

	st.mu.Lock()
	st.stat.Running = false
	st.stat.Runs++
	st.stat.LastDuration = elapsed
	if err != nil {
		st.stat.Failures++
		st.stat.LastError = err.Error()
	} else {
		st.stat.LastError = ""
	}
	st.mu.Unlock()

	switch {
	case errors.Is(err, context.DeadlineExceeded):
		s.log.Emit(events.New(events.TaskTimeout).
			WithField("Task", t.Name).
			WithField("Timeout", timeout).
			WithField("Interval", t.Interval))
	case err != nil && !errors.Is(err, context.Canceled):
		s.log.Emit(events.New(events.CollectorError).
			WithField("Collector", t.Name).
			WithField("Error", err).
			WithField("Consecutive", s.consecutiveFailures(t.Name)))
	}
	// Running longer than the interval means the schedule cannot be honoured; that is
	// worth telling the operator about, because it usually means an unreachable target.
	if !manual && t.Interval > 0 && elapsed > t.Interval {
		st.mu.Lock()
		st.stat.Skips++
		st.mu.Unlock()
		s.log.Emit(events.New(events.SchedulerTaskSkip).
			WithField("Task", t.Name).
			WithField("Interval", t.Interval).
			WithField("RunningFor", elapsed))
	}
	return err
}

func (s *Scheduler) consecutiveFailures(name string) int64 {
	st := s.state(name)
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.stat.LastError == "" {
		return 0
	}
	return st.stat.Failures
}

func (s *Scheduler) state(name string) *taskState {
	s.mu.RLock()
	st, ok := s.states[name]
	s.mu.RUnlock()
	if ok {
		return st
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if st, ok := s.states[name]; ok {
		return st
	}
	st = &taskState{stat: TaskStat{Name: name}, manual: make(chan chan error, 1)}
	s.states[name] = st
	return st
}

func (s *Scheduler) setNextRun(st *taskState, t time.Time) {
	st.mu.Lock()
	st.stat.NextRun = t
	st.mu.Unlock()
}

// Trigger runs a task out of band and waits for it to finish. Used by the manual test
// endpoints and by the CLI.
func (s *Scheduler) Trigger(ctx context.Context, name string) error {
	s.mu.RLock()
	_, known := s.states[name]
	s.mu.RUnlock()
	if !known {
		return fmt.Errorf("scheduler: no such task %q", name)
	}
	st := s.state(name)
	reply := make(chan error, 1)
	select {
	case st.manual <- reply:
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(2 * time.Second):
		return fmt.Errorf("scheduler: task %q is busy", name)
	}
	select {
	case err := <-reply:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Stats returns a snapshot of every task's statistics, ordered by name.
func (s *Scheduler) Stats() []TaskStat {
	s.mu.RLock()
	names := make([]string, 0, len(s.states))
	for n := range s.states {
		names = append(names, n)
	}
	s.mu.RUnlock()
	sort.Strings(names)

	out := make([]TaskStat, 0, len(names))
	for _, n := range names {
		st := s.state(n)
		st.mu.Lock()
		out = append(out, st.stat)
		st.mu.Unlock()
	}
	return out
}

// TaskNames lists the registered task names.
func (s *Scheduler) TaskNames() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.tasks))
	for _, t := range s.tasks {
		out = append(out, t.Name)
	}
	sort.Strings(out)
	return out
}
