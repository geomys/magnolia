package lockstep

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"geomys.org/magnolia/internal/acmeerrors"
	"geomys.org/magnolia/internal/durable"
	"geomys.org/magnolia/internal/immutable"

	"github.com/prometheus/client_golang/prometheus"
)

// Backend is an object storage. It is dedicated to a single log pair.
//
// It can be eventually consistent, but writes must be durable once they return.
//
// The Upload and Fetch methods must be usable concurrently.
type Backend interface {
	// Upload writes the value for a key. Upload is expected to retry transient
	// errors, and only return an error for unrecoverable errors. When Upload
	// returns, the object must be fully persisted. opts may be nil.
	Upload(ctx context.Context, key string, data []byte, opts *UploadOptions) error

	// Fetch returns the value for a key.
	Fetch(ctx context.Context, key string) ([]byte, error)

	// Discard suggests to the backend that the key can be deleted.
	Discard(ctx context.Context, key string) error

	// Metrics returns the metrics to register for this log. The metrics should
	// not be shared by any other logs.
	Metrics() []prometheus.Collector
}

// UploadOptions are used as part of the Backend.Upload method, and are
// marshaled to JSON and stored in the staging bundles.
type UploadOptions struct {
	// ContentType is the MIME type of the data. If empty, defaults to
	// "application/octet-stream".
	ContentType string

	// Compressed is true if the data is compressed with gzip.
	Compressed bool

	// Immutable is true if the data is never changed after being uploaded.
	// Note that the same value may still be re-uploaded, and must succeed.
	// [Backend.Discard] can still be used on immutable entries.
	Immutable bool
}

var optsHashTile = &UploadOptions{Immutable: true}
var optsDataTile = &UploadOptions{Compressed: true, Immutable: true}
var optsStaging = &UploadOptions{Compressed: true} // not immutable, see [stagingPath]
var optsCheckpoint = &UploadOptions{ContentType: "text/plain; charset=utf-8"}

type LocalBackend struct {
	dir      string
	metrics  []prometheus.Collector
	duration prometheus.SummaryVec
	log      *slog.Logger
}

func NewLocalBackend(ctx context.Context, dir string, l *slog.Logger) (*LocalBackend, error) {
	duration := prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "fs_op_duration_seconds",
			Help:       "Overall local backend operation latency.",
			Objectives: map[float64]float64{0.5: 0.05, 0.75: 0.025, 0.9: 0.01, 0.99: 0.001},
			MaxAge:     1 * time.Minute,
			AgeBuckets: 6,
		},
		[]string{"method"},
	)
	if fi, err := os.Stat(dir); err != nil && !os.IsNotExist(err) {
		return nil, acmeerrors.Internal("failed to stat local backend directory %q: %w", dir, err)
	} else if err == nil && !fi.IsDir() {
		return nil, acmeerrors.Internal("local backend path %q is not a directory", dir)
	}
	return &LocalBackend{
		dir:      dir,
		metrics:  []prometheus.Collector{duration},
		duration: *duration,
		log:      l,
	}, nil
}

var _ Backend = &LocalBackend{}

func (s *LocalBackend) Upload(ctx context.Context, key string, data []byte, opts *UploadOptions) (err error) {
	defer prometheus.NewTimer(s.duration.WithLabelValues("upload")).ObserveDuration()
	name, err := filepath.Localize(key)
	if err != nil {
		return acmeerrors.Internal("failed to localize key %q as a filesystem path: %w", key, err)
	}
	path := filepath.Join(s.dir, name)
	if err := durable.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return acmeerrors.Internal("failed to create directory %q: %w", filepath.Dir(path), err)
	}
	var perms os.FileMode = 0644
	if opts != nil && opts.Immutable {
		perms = 0444
		if f, err := os.Open(path); err == nil {
			defer f.Close()
			if err := compareFile(f, data); err != nil {
				return acmeerrors.Internal("immutable file %q already exists and does not match: %w", path, err)
			}
			s.log.WarnContext(ctx, "local file already exists", "key", key, "path", path)
			return nil
		}
		// As a best effort, try to set the immutable flag if supported by the
		// OS, and the process has the appropriate capabilities.
		defer func() {
			if err != nil {
				return
			}
			var f *os.File
			f, err = os.Open(path)
			if err != nil {
				return
			}
			immutable.Set(f)
			err = f.Close()
		}()
	}
	s.log.DebugContext(ctx, "local file write", "key", key,
		"size", len(data), "path", path, "perms", perms)
	return durable.WriteFile(path, data, perms)
}

func (s *LocalBackend) Fetch(ctx context.Context, key string) ([]byte, error) {
	defer prometheus.NewTimer(s.duration.WithLabelValues("fetch")).ObserveDuration()
	name, err := filepath.Localize(key)
	if err != nil {
		return nil, acmeerrors.Internal("failed to localize key %q as a filesystem path: %w", key, err)
	}
	path := filepath.Join(s.dir, name)
	s.log.DebugContext(ctx, "local file read", "key", key, "path", path)
	return os.ReadFile(path)
}

func (s *LocalBackend) Discard(ctx context.Context, key string) error {
	defer prometheus.NewTimer(s.duration.WithLabelValues("discard")).ObserveDuration()
	name, err := filepath.Localize(key)
	if err != nil {
		return acmeerrors.Internal("failed to localize key %q as a filesystem path: %w", key, err)
	}
	path := filepath.Join(s.dir, name)
	s.log.DebugContext(ctx, "local file delete", "key", key, "path", path)
	f, err := os.Open(path)
	if err != nil {
		return acmeerrors.Internal("failed to open file to be deleted %q: %w", path, err)
	}
	immutable.Unset(f)
	if err := f.Close(); err != nil {
		return acmeerrors.Internal("failed to close file to be deleted %q: %w", path, err)
	}
	return os.Remove(path)
}

func (s *LocalBackend) Metrics() []prometheus.Collector {
	return s.metrics
}

func compareFile(f *os.File, data []byte) error {
	b := make([]byte, min(len(data), 16384))
	for {
		n, err := f.Read(b)
		if err != nil && err != io.EOF {
			return err
		}
		if n > len(data) || !bytes.Equal(b[:n], data[:n]) {
			return errors.New("file contents do not match")
		}
		data = data[n:]
		if err == io.EOF {
			if len(data) == 0 {
				return nil
			}
			return errors.New("file contents do not match")
		}
	}
}
