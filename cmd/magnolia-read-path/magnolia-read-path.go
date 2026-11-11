// Command magnolia-read-path runs the read path of an MTC CA: it serves the
// logs and the certificates from the files written by magnolia-ca.
// See doc/urls.md.
//
// It reads the magnolia-ca config file (specified with -c, by default
// magnolia-ca.yaml), the keys are documented in the [caconfig.Config] type.
// It listens on the ReadListen addresses.
//
// Metrics are exposed publicly at /metrics, and logs are written to stderr.
// /health returns 500 if the checkpoint of the issuance or evidence log is
// stale, or if it's not signed correctly.
//
// A private HTTP debug server is also started on a random port on localhost.
// It serves the net/http/pprof endpoints.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"geomys.org/magnolia/internal/caconfig"
	"geomys.org/magnolia/internal/readpath"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

func main() {
	fs := flag.NewFlagSet("magnolia-read-path", flag.ExitOnError)
	configFlag := fs.String("c", "magnolia-ca.yaml", "path to the config file")
	fs.Parse(os.Args[1:])

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	go func() {
		ln, err := net.Listen("tcp", "localhost:")
		if err != nil {
			logger.Error("failed to start debug server", "err", err)
		} else {
			logger.Info("debug server listening", "addr", ln.Addr())
			err := http.Serve(ln, nil)
			logger.Error("debug server exited", "err", err)
		}
	}()

	c, err := caconfig.Load(*configFlag)
	if err != nil {
		fatalError(logger, "failed to load config file", "err", err)
	}

	mux := http.NewServeMux()

	metrics := prometheus.NewRegistry()
	metrics.MustRegister(collectors.NewGoCollector())
	metrics.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	metricsHandler := promhttp.HandlerFor(metrics, promhttp.HandlerOpts{
		ErrorLog: slog.NewLogLogger(logger.Handler().WithAttrs(
			[]slog.Attr{slog.String("source", "metrics")},
		), slog.LevelWarn),
	})
	magnoliaMetrics := prometheus.WrapRegistererWithPrefix("magnolia_read_", metrics)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	issuerLogger := logger.With("ca", c.Issuer.CAID)
	caVerifier, evidenceVerifier, err := c.Issuer.Verifiers()
	if err != nil {
		fatalError(issuerLogger, "failed to load verifier keys", "err", err)
	}
	notBefore, err := c.Issuer.NotBeforeDate()
	if err != nil {
		fatalError(issuerLogger, "failed to load CA certificate notBefore", "err", err)
	}
	nonceKey, err := caconfig.ReadNonceKey(c.NonceKey)
	if err != nil {
		fatalError(logger, "failed to load nonce key", "err", err)
	}
	root, err := os.OpenRoot(c.Issuer.LocalDirectory)
	if err != nil {
		fatalError(issuerLogger, "failed to open local directory", "err", err)
	}
	rp, err := readpath.New(readpath.Config{
		CAID:             c.Issuer.CAID,
		ReadPrefix:       c.Issuer.ReadPrefix,
		WritePrefix:      c.WritePrefix,
		NonceKey:         nonceKey,
		Files:            root.FS(),
		CAVerifier:       caVerifier,
		EvidenceVerifier: evidenceVerifier,
		NotBefore:        notBefore,
	})
	if err != nil {
		fatalError(issuerLogger, "failed to create read path", "err", err)
	}
	magnoliaMetrics.MustRegister(rp.Metrics()...)

	// Sequencing a pool can take a few seconds on top of the period, and
	// cosignature timestamps have a resolution of one second.
	maxCheckpointAge := c.Issuer.SequencingPeriod() + 5*time.Second
	healthHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if err := rp.CheckHealth(maxCheckpointAge); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "%s:\n%v\n", c.Issuer.CAID, err)
			return
		}
		fmt.Fprintf(w, "%s: OK\n", c.Issuer.CAID)
	})

	prefix, err := url.Parse(c.Issuer.ReadPrefix)
	if err != nil {
		fatalError(issuerLogger, "failed to parse ReadPrefix", "err", err)
	}
	mux.Handle(prefix.Host+prefix.Path+"/", rp.Handler())
	mux.Handle(prefix.Host+"/health", healthHandler)
	mux.Handle(prefix.Host+"/metrics", metricsHandler)

	s := &http.Server{
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 15 * time.Second,
		ErrorLog: slog.NewLogLogger(logger.Handler().WithAttrs(
			[]slog.Attr{slog.String("source", "http")},
		), slog.LevelWarn),
	}
	if c.ACME.Cache != "" {
		m := &autocert.Manager{
			Cache:      autocert.DirCache(c.ACME.Cache),
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(prefix.Hostname()),
			Client: &acme.Client{
				DirectoryURL: c.ACME.Directory,
				UserAgent:    "geomys.org/magnolia",
			},
		}
		s.TLSConfig = m.TLSConfig()
	} else {
		protocols := new(http.Protocols)
		protocols.SetHTTP1(true)
		protocols.SetUnencryptedHTTP2(true)
		s.Protocols = protocols
	}

	if len(c.ReadListen) == 0 {
		fatalError(logger, "no ReadListen addresses specified in config")
	}
	for _, addr := range c.ReadListen {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			fatalError(logger, "failed to listen", "addr", addr, "err", err)
		}
		logger.Info("listening", "addr", l.Addr())
		go func() {
			var err error
			if s.TLSConfig != nil {
				err = s.ServeTLS(l, "", "")
			} else {
				err = s.Serve(l)
			}
			if !errors.Is(err, http.ErrServerClosed) {
				logger.Error("serve error", "err", err)
				stop()
			}
		}()
	}

	<-ctx.Done()
	logger.Info("shutting down")
	if err := s.Close(); err != nil {
		logger.Error("failed to close server", "err", err)
	}

	os.Exit(1)
}

func fatalError(logger *slog.Logger, msg string, args ...any) {
	logger.Error(msg, args...)
	os.Exit(1)
}
