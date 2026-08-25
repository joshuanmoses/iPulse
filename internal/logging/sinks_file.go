package logging

import (
	"os"

	"github.com/ipulse/ipulse/internal/events"
)

// textSink writes readable syslog-style records. Each record starts with a timestamped
// header line, so record boundaries stay obvious even though bodies are multi-line.
type textSink struct{ f *rotatingFile }

func newTextSink(cfg rotateConfig) (*textSink, error) {
	f, err := newRotatingFile(cfg)
	if err != nil {
		return nil, err
	}
	return &textSink{f: f}, nil
}

func (s *textSink) Name() string { return "text" }

func (s *textSink) Write(ev events.Event) error {
	_, err := s.f.Write(append([]byte(ev.Text()), '\n'))
	return err
}

func (s *textSink) Close() error                  { return s.f.Close() }
func (s *textSink) takeRotations() []RotationInfo { return s.f.takeRotations() }

// jsonlSink writes one JSON object per line for log shippers and offline analysis.
type jsonlSink struct{ f *rotatingFile }

func newJSONLSink(cfg rotateConfig) (*jsonlSink, error) {
	f, err := newRotatingFile(cfg)
	if err != nil {
		return nil, err
	}
	return &jsonlSink{f: f}, nil
}

func (s *jsonlSink) Name() string { return "jsonl" }

func (s *jsonlSink) Write(ev events.Event) error {
	b, err := ev.JSON()
	if err != nil {
		return err
	}
	_, err = s.f.Write(append(b, '\n'))
	return err
}

func (s *jsonlSink) Close() error                  { return s.f.Close() }
func (s *jsonlSink) takeRotations() []RotationInfo { return s.f.takeRotations() }

// consoleSink writes one-line records to stderr, for foreground and container use.
type consoleSink struct{ out *os.File }

func newConsoleSink() *consoleSink { return &consoleSink{out: os.Stderr} }

func (s *consoleSink) Name() string { return "console" }

func (s *consoleSink) Write(ev events.Event) error {
	_, err := s.out.WriteString(ev.OneLine() + "\n")
	return err
}

func (s *consoleSink) Close() error { return nil }
