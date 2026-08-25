package logging

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// rotatingFile is a size- and age-based rotating log file with optional gzip
// compression of archives. It is deliberately self-contained: an agent that must run
// unattended for months cannot depend on an external log rotator being configured.
type rotatingFile struct {
	mu sync.Mutex

	path          string
	maxBytes      int64
	maxArchives   int
	retentionDays int
	compress      bool
	rotateDaily   bool
	mode          os.FileMode

	f    *os.File
	size int64
	day  int // year-day of the current file, for daily rotation

	rotations []RotationInfo
}

type rotateConfig struct {
	Path          string
	MaxBytes      int64
	MaxArchives   int
	RetentionDays int
	Compress      bool
	RotateDaily   bool
	Mode          os.FileMode
}

func newRotatingFile(cfg rotateConfig) (*rotatingFile, error) {
	if cfg.Mode == 0 {
		cfg.Mode = 0o640
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = 100 << 20
	}
	r := &rotatingFile{
		path: cfg.Path, maxBytes: cfg.MaxBytes, maxArchives: cfg.MaxArchives,
		retentionDays: cfg.RetentionDays, compress: cfg.Compress,
		rotateDaily: cfg.RotateDaily, mode: cfg.Mode,
	}
	if err := os.MkdirAll(filepath.Dir(cfg.Path), 0o750); err != nil {
		return nil, fmt.Errorf("logging: create log directory: %w", err)
	}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *rotatingFile) open() error {
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, r.mode)
	if err != nil {
		return fmt.Errorf("logging: open %s: %w", r.path, err)
	}
	// Enforce the mode even when the file already existed with looser permissions.
	if err := f.Chmod(r.mode); err != nil && !os.IsPermission(err) {
		_ = err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	r.f = f
	r.size = st.Size()
	r.day = fileDay(st.ModTime())
	return nil
}

func fileDay(t time.Time) int { return t.Year()*1000 + t.YearDay() }

// Write appends a record, rotating first when the record would exceed the size limit
// or when the calendar day has changed and daily rotation is enabled.
func (r *rotatingFile) Write(b []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		if err := r.open(); err != nil {
			return 0, err
		}
	}
	now := time.Now()
	if r.size > 0 && (r.size+int64(len(b)) > r.maxBytes || (r.rotateDaily && fileDay(now) != r.day)) {
		if err := r.rotate(now); err != nil {
			// Rotation failure must not lose the record: keep writing to the current
			// file and report the problem through the sink error path.
			_ = err
		}
	}
	n, err := r.f.Write(b)
	r.size += int64(n)
	return n, err
}

// rotate closes the current file, renames it with a timestamp, optionally compresses
// it, prunes old archives and opens a fresh file.
func (r *rotatingFile) rotate(now time.Time) error {
	if err := r.f.Close(); err != nil {
		return err
	}
	r.f = nil

	archive := fmt.Sprintf("%s.%s", r.path, now.Format("20060102-150405"))
	if err := os.Rename(r.path, archive); err != nil {
		_ = r.open()
		return err
	}
	info := RotationInfo{File: r.path, Archive: archive, SizeBytes: r.size}

	if r.compress {
		if gz, err := compressFile(archive, r.mode); err == nil {
			_ = os.Remove(archive)
			info.Archive = gz
			info.Compressed = true
		}
	}
	retained, deleted := r.pruneArchives(now)
	info.ArchivesRetained, info.ArchivesDeleted = retained, deleted

	r.size = 0
	if err := r.open(); err != nil {
		return err
	}
	r.rotations = append(r.rotations, info)
	return nil
}

// pruneArchives enforces both the archive-count and the age limit.
func (r *rotatingFile) pruneArchives(now time.Time) (retained, deleted int) {
	dir := filepath.Dir(r.path)
	base := filepath.Base(r.path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, 0
	}
	type archive struct {
		path string
		mod  time.Time
	}
	var archives []archive
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || name == base || !strings.HasPrefix(name, base+".") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		archives = append(archives, archive{filepath.Join(dir, name), info.ModTime()})
	}
	// Newest first, so the tail is what gets dropped.
	sort.Slice(archives, func(i, j int) bool { return archives[i].mod.After(archives[j].mod) })

	cutoff := time.Time{}
	if r.retentionDays > 0 {
		cutoff = now.AddDate(0, 0, -r.retentionDays)
	}
	for i, a := range archives {
		tooMany := r.maxArchives > 0 && i >= r.maxArchives
		tooOld := !cutoff.IsZero() && a.mod.Before(cutoff)
		if tooMany || tooOld {
			if os.Remove(a.path) == nil {
				deleted++
			}
			continue
		}
		retained++
	}
	return retained, deleted
}

func compressFile(path string, mode os.FileMode) (string, error) {
	in, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer in.Close()
	out, err := os.OpenFile(path+".gz", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return "", err
	}
	defer out.Close()
	zw := gzip.NewWriter(out)
	if _, err := io.Copy(zw, in); err != nil {
		_ = zw.Close()
		return "", err
	}
	if err := zw.Close(); err != nil {
		return "", err
	}
	return path + ".gz", nil
}

func (r *rotatingFile) takeRotations() []RotationInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.rotations) == 0 {
		return nil
	}
	out := r.rotations
	r.rotations = nil
	return out
}

func (r *rotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}
