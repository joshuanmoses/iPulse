package logging

import (
	"context"
	"time"

	"github.com/ipulse/ipulse/internal/database"
	"github.com/ipulse/ipulse/internal/events"
)

// dbSink stores events in the searchable SQLite events table.
type dbSink struct {
	db *database.DB
}

func newDBSink(db *database.DB) *dbSink { return &dbSink{db: db} }

func (s *dbSink) Name() string { return "database" }

func (s *dbSink) Write(ev events.Event) error {
	_, err := s.WriteWithID(ev)
	return err
}

// WriteWithID stores the event and returns its row id, which the logger republishes so
// downstream consumers (correlation, API) can reference stored events.
func (s *dbSink) WriteWithID(ev events.Event) (int64, error) {
	// A short bound: a database stall must not hold up the log pipeline.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return s.db.InsertEvent(ctx, ev)
}

func (s *dbSink) Close() error { return nil }
