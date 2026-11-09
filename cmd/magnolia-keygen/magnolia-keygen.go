// Command magnolia-keygen creates the keys and logs of a magnolia-ca instance,
// and prints its public keys.
//
// It reads the magnolia-ca config file (specified with -c, by default
// magnolia-ca.yaml), and creates the nonce key, the accounts database, the
// issuer seed, the lock database, and the logs, if they don't exist yet. It is
// safe to run again, to print the public keys.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"os"

	"filippo.io/torchwood"
	"geomys.org/magnolia/internal/ca"
	"geomys.org/magnolia/internal/caconfig"
	"geomys.org/magnolia/internal/lockstep"
)

func main() {
	flags := flag.NewFlagSet("magnolia-keygen", flag.ExitOnError)
	configFlag := flags.String("c", "magnolia-ca.yaml", "path to the config file")
	flags.Parse(os.Args[1:])

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ctx := context.Background()

	c, err := caconfig.Load(*configFlag)
	if err != nil {
		fatalError(logger, "failed to load config file", "err", err)
	}

	if err := caconfig.GenerateNonceKey(c.NonceKey); errors.Is(err, fs.ErrExist) {
		logger.Info("nonce key exists", "path", c.NonceKey)
	} else if err != nil {
		fatalError(logger, "failed to create nonce key", "err", err)
	} else {
		logger.Info("created nonce key", "path", c.NonceKey)
	}

	if err := ca.CreateAccounts(c.Accounts); errors.Is(err, fs.ErrExist) {
		logger.Info("accounts database exists", "path", c.Accounts)
	} else if err != nil {
		fatalError(logger, "failed to create accounts database", "err", err)
	} else {
		logger.Info("created accounts database", "path", c.Accounts)
	}

	logger = logger.With("ca", c.Issuer.CAID)
	if err := caconfig.GenerateIssuerSeed(c.Issuer.Seed, c.Issuer.CAID); errors.Is(err, fs.ErrExist) {
		logger.Info("issuer seed exists", "path", c.Issuer.Seed)
	} else if err != nil {
		fatalError(logger, "failed to create issuer seed", "err", err)
	} else {
		logger.Info("created issuer seed", "path", c.Issuer.Seed)
	}

	if err := lockstep.CreateSQLiteLockDatabase(c.Issuer.Lock); errors.Is(err, fs.ErrExist) {
		logger.Info("lock database exists", "path", c.Issuer.Lock)
	} else if err != nil {
		fatalError(logger, "failed to create lock database", "err", err)
	} else {
		logger.Info("created lock database", "path", c.Issuer.Lock)
	}

	caCosigner, evidenceSigner, err := c.Issuer.Signers()
	if err != nil {
		fatalError(logger, "failed to load issuer seed", "err", err)
	}
	backend, err := lockstep.NewLocalBackend(ctx, c.Issuer.LocalDirectory, logger)
	if err != nil {
		fatalError(logger, "failed to open local directory", "err", err)
	}
	// Creating the logs signs their first checkpoints, and stores them in the
	// lock database.
	signer, err := lockstep.NewSQLiteSigner(ctx, c.Issuer.Lock, logger,
		c.Issuer.IssuanceOrigin(), []*torchwood.CosignatureSigner{caCosigner},
		c.Issuer.EvidenceOrigin, []*torchwood.CosignatureSigner{evidenceSigner})
	if err != nil {
		fatalError(logger, "failed to open lock database", "err", err)
	}
	err = ca.CreateIssuer(ctx, ca.IssuerConfig{
		CAID:       c.Issuer.CAID,
		ReadPrefix: c.Issuer.ReadPrefix,
		Logs: lockstep.Config{
			Logger:            logger,
			Backend:           backend,
			Signer:            signer,
			IssuanceOrigin:    c.Issuer.IssuanceOrigin(),
			IssuanceVerifiers: []*torchwood.CosignatureVerifier{caCosigner.Verifier()},
			EvidenceOrigin:    c.Issuer.EvidenceOrigin,
			EvidenceVerifiers: []*torchwood.CosignatureVerifier{evidenceSigner.Verifier()},
		},
		SequencingPeriod: c.Issuer.SequencingPeriod(),
	})
	if errors.Is(err, lockstep.ErrLogExists) {
		logger.Info("logs exist")
	} else if err != nil {
		fatalError(logger, "failed to create logs", "err", err)
	}
	if err := signer.Close(); err != nil {
		fatalError(logger, "failed to close lock database", "err", err)
	}

	fmt.Printf("CA cosigner vkey: %s\n", caCosigner.Verifier())
	fmt.Printf("Evidence log vkey: %s\n", evidenceSigner.Verifier())
}

func fatalError(logger *slog.Logger, msg string, args ...any) {
	logger.Error(msg, args...)
	os.Exit(1)
}
