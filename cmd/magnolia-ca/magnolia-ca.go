// Command magnolia-ca runs the ACME write path of an MTC CA.
//
// A YAML config file is required (specified with -c, by default
// magnolia-ca.yaml), the keys are documented in the [caconfig.Config] type.
// The keys and logs must be created first with magnolia-keygen.
//
// Metrics are exposed publicly at /metrics, and logs are written to stderr.
//
// A private HTTP debug server is also started on a random port on localhost. It
// serves the net/http/pprof endpoints.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"filippo.io/torchwood"
	"geomys.org/magnolia/internal/ca"
	"geomys.org/magnolia/internal/caconfig"
	"geomys.org/magnolia/internal/lockstep"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

func main() {
	fs := flag.NewFlagSet("magnolia-ca", flag.ExitOnError)
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

	healthHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	metrics := prometheus.NewRegistry()
	metrics.MustRegister(collectors.NewGoCollector())
	metrics.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	metricsHandler := promhttp.HandlerFor(metrics, promhttp.HandlerOpts{
		ErrorLog: slog.NewLogLogger(logger.Handler().WithAttrs(
			[]slog.Attr{slog.String("source", "metrics")},
		), slog.LevelWarn),
	})
	magnoliaMetrics := prometheus.WrapRegistererWithPrefix("magnolia_", metrics)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	issuerLogger := logger.With("ca", c.Issuer.CAID)
	caCosigner, evidenceSigner, err := c.Issuer.Signers()
	if err != nil {
		fatalError(issuerLogger, "failed to load issuer seed", "err", err)
	}
	backend, err := lockstep.NewLocalBackend(ctx, c.Issuer.LocalDirectory, issuerLogger)
	if err != nil {
		fatalError(issuerLogger, "failed to open local directory", "err", err)
	}
	magnoliaMetrics.MustRegister(backend.Metrics()...)
	// NewSQLiteSigner would fail too, but suggest the wrong fix.
	if _, err := os.Stat(c.Issuer.Lock); err != nil {
		fatalError(issuerLogger, "lock database must be created with magnolia-keygen", "err", err)
	}
	signer, err := lockstep.NewSQLiteSigner(ctx, c.Issuer.Lock, issuerLogger,
		c.Issuer.IssuanceOrigin(), []*torchwood.CosignatureSigner{caCosigner},
		c.Issuer.EvidenceOrigin, []*torchwood.CosignatureSigner{evidenceSigner})
	if err != nil {
		fatalError(issuerLogger, "failed to open lock database", "err", err)
	}
	magnoliaMetrics.MustRegister(signer.Metrics()...)
	iss, err := ca.LoadIssuer(ctx, ca.IssuerConfig{
		CAID:       c.Issuer.CAID,
		ReadPrefix: c.Issuer.ReadPrefix,
		Logs: lockstep.Config{
			Logger:            issuerLogger,
			Backend:           backend,
			Signer:            signer,
			PoolSize:          c.Issuer.PoolSize,
			IssuanceOrigin:    c.Issuer.IssuanceOrigin(),
			IssuanceVerifiers: []*torchwood.CosignatureVerifier{caCosigner.Verifier()},
			EvidenceOrigin:    c.Issuer.EvidenceOrigin,
			EvidenceVerifiers: []*torchwood.CosignatureVerifier{evidenceSigner.Verifier()},
		},
		SequencingPeriod: c.Issuer.SequencingPeriod(),
	})
	if errors.Is(err, lockstep.ErrLogNotFound) {
		fatalError(issuerLogger, "logs not found, create them with magnolia-keygen", "err", err)
	} else if err != nil {
		fatalError(issuerLogger, "failed to load issuer", "err", err)
	}

	nonceKey, err := caconfig.ReadNonceKey(c.NonceKey)
	if err != nil {
		fatalError(logger, "failed to load nonce key", "err", err)
	}

	prefix, err := url.Parse(c.WritePrefix)
	if err != nil {
		fatalError(logger, "failed to parse WritePrefix", "err", err)
	}
	if _, err := os.Stat(c.Accounts); err != nil {
		fatalError(logger, "accounts database must be created with magnolia-keygen", "err", err)
	}
	cc, err := ca.New(ca.Config{
		WritePrefix: c.WritePrefix,
		NonceKey:    nonceKey,
		Accounts:    c.Accounts,
		Issuer:      iss,
	})
	if err != nil {
		fatalError(logger, "failed to create CA", "err", err)
	}
	mux.Handle(prefix.Host+prefix.Path+"/", cc.Handler())
	mux.Handle(prefix.Host+"/health", healthHandler)
	mux.Handle(prefix.Host+"/metrics", metricsHandler)

	s := &http.Server{
		Handler:     mux,
		ReadTimeout: 5 * time.Second,
		// Finalize requests wait for the certificate to be issued.
		WriteTimeout: 45 * time.Second,
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

	if len(c.Listen) == 0 {
		fatalError(logger, "no Listen addresses specified in config")
	}
	for _, addr := range c.Listen {
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

	// Shutdown doesn't wait for in-flight requests. Orders are held in memory,
	// so they would be lost on restart anyway, and finalize requests waiting
	// for issuance fail as soon as the sequencer stops.
	err = iss.RunSequencer(ctx)
	if ctx.Err() != nil {
		logger.Info("shutting down", "err", err)
	} else {
		logger.Error("sequencer error", "err", err)
	}
	if err := s.Close(); err != nil {
		logger.Error("failed to close server", "err", err)
	}
	if err := cc.Close(); err != nil {
		logger.Error("failed to close CA", "err", err)
	}
	if err := signer.Close(); err != nil {
		logger.Error("failed to close lock database", "err", err)
	}

	os.Exit(1)
}

func fatalError(logger *slog.Logger, msg string, args ...any) {
	logger.Error(msg, args...)
	os.Exit(1)
}
