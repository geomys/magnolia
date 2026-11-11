// Package readpath implements the read path of an issuer: an HTTP handler that
// serves its logs and certificates from the files written by magnolia-ca.
//
// The URLs and the files they are served from are described in doc/urls.md.
package readpath

import (
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"crypto/mldsa"

	"filippo.io/torchwood"
	"geomys.org/magnolia/internal/acmeerrors"
	"geomys.org/magnolia/internal/mtc"
	"geomys.org/magnolia/internal/nonce"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/mod/sumdb/note"
)

type Config struct {
	// CAID is the CA ID, such as "66252.1".
	CAID string

	// ReadPrefix is the absolute URL prefix of the read path of the issuer,
	// without a trailing slash, such as "https://read.example.com/66252.1".
	ReadPrefix string

	// WritePrefix is the absolute URL prefix of the ACME server, without a
	// trailing slash, such as "https://acme.example.com". Certificates link
	// to its directory.
	WritePrefix string

	// NonceKey is the nonce key of the ACME server, to mint the nonces
	// returned to POST-as-GET requests for certificates.
	NonceKey []byte

	// Files is the local directory of the issuer.
	Files fs.FS

	// CAVerifier and EvidenceVerifier are the verifiers of the CA cosigner and
	// of the evidence log, for [ReadPath.CheckHealth]. CAVerifier is also the
	// public key of the CA certificate.
	CAVerifier       *torchwood.CosignatureVerifier
	EvidenceVerifier *torchwood.CosignatureVerifier

	// NotBefore is the day the CA cosigner key was generated, the notBefore
	// of the CA certificate.
	NotBefore time.Time
}

type ReadPath struct {
	caID       mtc.TrustAnchorID
	prefix     *url.URL
	directory  string
	nonces     *nonce.Issuer
	files      fs.FS
	caVerifier *torchwood.CosignatureVerifier
	evVerifier *torchwood.CosignatureVerifier
	caPEM      []byte

	reqCount    *prometheus.CounterVec
	reqDuration *prometheus.SummaryVec
	resSize     *prometheus.SummaryVec
}

func New(c Config) (*ReadPath, error) {
	caID, err := mtc.ParseTrustAnchorID(c.CAID)
	if err != nil {
		return nil, err
	}
	prefix, err := parsePrefix("ReadPrefix", c.ReadPrefix)
	if err != nil {
		return nil, err
	}
	writePrefix, err := parsePrefix("WritePrefix", c.WritePrefix)
	if err != nil {
		return nil, err
	}
	nonces, err := nonce.NewIssuer(c.NonceKey)
	if err != nil {
		return nil, err
	}
	if c.Files == nil {
		return nil, errors.New("missing Files")
	}
	if c.CAVerifier == nil {
		return nil, errors.New("missing CAVerifier")
	}
	if name := oidPrefix + caID.String(); c.CAVerifier.Name() != name {
		return nil, fmt.Errorf("CAVerifier is %q, expected %q", c.CAVerifier.Name(), name)
	}
	if c.EvidenceVerifier == nil {
		return nil, errors.New("missing EvidenceVerifier")
	}
	caKey, ok := c.CAVerifier.PublicKey().(*mldsa.PublicKey)
	if !ok {
		return nil, errors.New("CAVerifier is not an ML-DSA cosigner")
	}
	caCert, err := mtc.CACertificate(&mtc.CATemplate{
		CAID:      caID,
		NotBefore: c.NotBefore,
		PublicKey: caKey,
		// The c2sp.org/mtc-tlog CA prefix URL, see doc/urls.md.
		PrefixURLs: []string{prefix.String() + "/issuance"},
	})
	if err != nil {
		return nil, fmt.Errorf("couldn't build CA certificate: %w", err)
	}
	return &ReadPath{
		caID:       caID,
		prefix:     prefix,
		directory:  writePrefix.String() + "/directory",
		nonces:     nonces,
		files:      filesOnlyFS{c.Files},
		caVerifier: c.CAVerifier,
		evVerifier: c.EvidenceVerifier,
		caPEM:      pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert}),

		reqCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "http_requests_total",
				Help: "HTTP requests served.",
			},
			[]string{"log", "kind", "code"},
		),
		reqDuration: prometheus.NewSummaryVec(
			prometheus.SummaryOpts{
				Name:       "http_request_duration_seconds",
				Help:       "HTTP request serving latencies in seconds.",
				Objectives: map[float64]float64{0.5: 0.05, 0.75: 0.025, 0.9: 0.01, 0.99: 0.001},
				MaxAge:     1 * time.Minute,
				AgeBuckets: 6,
			},
			[]string{"log", "kind"},
		),
		resSize: prometheus.NewSummaryVec(
			prometheus.SummaryOpts{
				Name:       "http_response_size_bytes",
				Help:       "HTTP response sizes in bytes.",
				Objectives: map[float64]float64{0.5: 0.05, 0.75: 0.025, 0.9: 0.01, 0.99: 0.001},
				MaxAge:     1 * time.Minute,
				AgeBuckets: 6,
			},
			[]string{"log", "kind"},
		),
	}, nil
}

// oidPrefix is prepended to the ASCII representation of a trust anchor ID to
// represent it as a log origin or cosigner name, as specified in
// https://c2sp.org/mtc-tlog@v0.1.0#representing-trust-anchor-ids.
const oidPrefix = "oid/1.3.6.1.4.1."

// parsePrefix parses an absolute https URL prefix without a trailing slash.
func parsePrefix(name, prefix string) (*url.URL, error) {
	u, err := url.Parse(prefix)
	if err != nil {
		return nil, fmt.Errorf("invalid %s: %w", name, err)
	}
	switch {
	case u.Scheme != "https":
		return nil, fmt.Errorf("%s must be an https URL", name)
	case u.Host == "":
		return nil, fmt.Errorf("%s must have a host", name)
	case u.RawQuery != "" || u.Fragment != "" || u.User != nil:
		return nil, fmt.Errorf("%s must not have a query, fragment, or userinfo", name)
	case strings.HasSuffix(u.Path, "/"):
		return nil, fmt.Errorf("%s must not have a trailing slash", name)
	}
	return u, nil
}

// Metrics returns the metrics to register for this read path.
func (rp *ReadPath) Metrics() []prometheus.Collector {
	return []prometheus.Collector{rp.reqCount, rp.reqDuration, rp.resSize}
}

const (
	cacheImmutable = "public, max-age=604800, immutable"
	cacheNever     = "no-store"
)

// Handler returns the handler of the URLs under the ReadPrefix.
func (rp *ReadPath) Handler() http.Handler {
	mux := http.NewServeMux()
	prefix := rp.prefix.Path
	mux.Handle("GET "+prefix+"/ca.pem", rp.instrument("", "ca",
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Content-Type", chainType)
			w.Header().Set("Cache-Control", cacheImmutable)
			w.Write(rp.caPEM)
		})))
	for _, log := range []string{"issuance", "evidence"} {
		mux.Handle("GET "+prefix+"/"+log+"/1/checkpoint", rp.instrument(log, "checkpoint",
			rp.file("text/plain; charset=utf-8", cacheNever, false, func(*http.Request) string {
				return log + "/checkpoint"
			})))
		mux.Handle("GET "+prefix+"/"+log+"/1/tile/{path...}", rp.instrument(log, "tile",
			rp.file("application/octet-stream", cacheImmutable, false, func(r *http.Request) string {
				return log + "/tile/" + r.PathValue("path")
			})))
		mux.Handle("GET "+prefix+"/"+log+"/1/tile/entries/{path...}", rp.instrument(log, "entries",
			rp.file("application/octet-stream", cacheImmutable, true, func(r *http.Request) string {
				return log + "/tile/entries/" + r.PathValue("path")
			})))
	}
	mux.Handle("GET "+prefix+"/issuance/1/subtrees/{path...}", rp.instrument("issuance", "subtrees",
		rp.file("application/octet-stream", cacheImmutable, false, func(r *http.Request) string {
			return "subtrees/" + r.PathValue("path")
		})))
	certificate := rp.instrument("issuance", "certificate", http.HandlerFunc(rp.serveCertificate))
	mux.Handle("GET "+prefix+"/certificate/1/{date}/{id}", certificate)
	mux.Handle("POST "+prefix+"/certificate/1/{date}/{id}", certificate)
	return mux
}

// instrument returns h with request metrics labeled with log and kind.
func (rp *ReadPath) instrument(log, kind string, h http.Handler) http.Handler {
	labels := prometheus.Labels{"log": log, "kind": kind}
	h = promhttp.InstrumentHandlerDuration(rp.reqDuration.MustCurryWith(labels), h)
	h = promhttp.InstrumentHandlerResponseSize(rp.resSize.MustCurryWith(labels), h)
	return promhttp.InstrumentHandlerCounter(rp.reqCount.MustCurryWith(labels), h)
}

// file returns a handler that serves the file named by fileName from the local
// directory. If gzip is set, the file is compressed at rest, and is served
// with Content-Encoding: gzip regardless of the Accept-Encoding of the request,
// as allowed by c2sp.org/tlog-tiles.
func (rp *ReadPath) file(contentType, cacheControl string, gzip bool, fileName func(*http.Request) string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := fileName(r)
		// Wildcards can match percent-encoded slashes.
		if !fs.ValidPath(name) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Cache-Control", cacheControl)
		if gzip {
			w.Header().Set("Content-Encoding", "gzip")
		}
		http.ServeFileFS(w, r, rp.files, name)
	})
}

// filesOnlyFS hides directories, so [http.ServeFileFS] serves 404s instead of
// directory listings (and of redirects to them).
type filesOnlyFS struct {
	fsys fs.FS
}

func (f filesOnlyFS) Open(name string) (fs.File, error) {
	file, err := f.fsys.Open(name)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if info.IsDir() {
		file.Close()
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	return file, nil
}

const (
	chainType      = "application/pem-certificate-chain"
	propertiesType = "application/pem-certificate-chain-with-properties"
)

// serveCertificate serves a standalone certificate, as the ACME certificate
// resource of RFC 8555, Section 7.4.2.
func (rp *ReadPath) serveCertificate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Link", `<`+rp.directory+`>;rel="index"`)
	cacheControl := cacheImmutable
	if r.Method == http.MethodPost {
		w.Header().Set("Replay-Nonce", rp.nonces.Mint())
		cacheControl = cacheNever
	}

	date := r.PathValue("date")
	if t, err := time.Parse(time.DateOnly, date); err != nil || t.Format(time.DateOnly) != date {
		writeError(w, errCertificateNotFound)
		return
	}

	// <index> is e.g. 1234567-ABCDEFGH in a URL.
	indexString, token, _ := strings.Cut(r.PathValue("id"), "-")
	index, perr := strconv.ParseInt(indexString, 10, 64)
	if perr != nil || index <= 0 || index >= 1<<48 || strconv.FormatInt(index, 10) != indexString {
		writeError(w, errCertificateNotFound)
		return
	}
	if len(token) != 8 || strings.ContainsFunc(token, func(r rune) bool {
		return (r < 'A' || r > 'Z') && (r < '2' || r > '7')
	}) {
		writeError(w, errCertificateNotFound)
		return
	}

	// The on-disk name is e.g. x001/x234/567-ABCDEFGH.
	name := indexPath(index) + "-" + token
	tbs, err := rp.readFile("certs/" + date + "/tbs/" + name)
	if err != nil {
		writeError(w, err)
		return
	}

	// The standalone file is the MTCProof up to the signatures field, which is
	// the subtrees file.
	standalone, err := rp.readFile("certs/" + date + "/standalone/" + name)
	if err != nil {
		writeError(w, err)
		return
	}
	s := cryptobyte.String(standalone)
	var start, end uint64
	if !s.Skip(2) || !s.ReadUint48(&start) || !s.ReadUint48(&end) {
		writeError(w, acmeerrors.Internal("malformed standalone proof"))
		return
	}
	signatures, err := rp.readFile("subtrees/" + indexPath(int64(start)) + "-" + strconv.FormatUint(end, 10))
	if err != nil {
		writeError(w, err)
		return
	}
	cert, cerr := mtc.Certificate(tbs, append(standalone, signatures...))
	if cerr != nil {
		writeError(w, acmeerrors.Internal("couldn't assemble certificate: %w", cerr))
		return
	}
	body := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})

	contentType := chainType
	if acceptsProperties(r) {
		properties, err := mtc.StandaloneProperties(rp.caID)
		if err != nil {
			writeError(w, acmeerrors.Internal("couldn't encode certificate properties: %w", err))
			return
		}
		contentType = propertiesType
		body = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE PROPERTIES", Bytes: properties}), body...)
	}

	w.Header().Set("Vary", "Accept")
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", cacheControl)
	w.Write(body)
}

var errCertificateNotFound = acmeerrors.Custom("certificateNotFound", 404, "certificate does not exist")

// indexPath formats n like a tile index in c2sp.org/tlog-tiles paths, like
// magnolia-ca does in file names.
func indexPath(n int64) string {
	s := fmt.Sprintf("%03d", n%1000)
	for n >= 1000 {
		n /= 1000
		s = fmt.Sprintf("x%03d/", n%1000) + s
	}
	return s
}

// readFile reads a file that makes up a certificate.
func (rp *ReadPath) readFile(name string) ([]byte, acmeerrors.Error) {
	b, err := fs.ReadFile(rp.files, name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errCertificateNotFound
	}
	if err != nil {
		return nil, acmeerrors.Internal("couldn't read certificate file: %w", err)
	}
	return b, nil
}

// acceptsProperties reports whether the request lists
// application/pem-certificate-chain-with-properties in its Accept header.
func acceptsProperties(r *http.Request) bool {
	for _, accept := range r.Header.Values("Accept") {
		for v := range strings.SplitSeq(accept, ",") {
			if mediaType, _, err := mime.ParseMediaType(v); err == nil && mediaType == propertiesType {
				return true
			}
		}
	}
	return false
}

func writeError(w http.ResponseWriter, err acmeerrors.Error) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Cache-Control", cacheNever)
	for k, v := range err.Headers() {
		w.Header().Set(k, v)
	}
	w.WriteHeader(err.Status())
	json.MarshalWrite(w, acmeerrors.Render(err))
}

// CheckHealth returns an error if the checkpoint of the issuance log is not
// signed by the CA cosigner, if the checkpoint of the evidence log is not
// signed by the evidence log, or if either is older than maxAge.
func (rp *ReadPath) CheckHealth(maxAge time.Duration) error {
	issuanceOrigin := oidPrefix + rp.caID.String() + ".0.1"
	var errs []error
	if err := rp.checkCheckpoint("issuance/checkpoint", issuanceOrigin, rp.caVerifier, maxAge); err != nil {
		errs = append(errs, fmt.Errorf("issuance log: %w", err))
	}
	if err := rp.checkCheckpoint("evidence/checkpoint", rp.evVerifier.Name(), rp.evVerifier, maxAge); err != nil {
		errs = append(errs, fmt.Errorf("evidence log: %w", err))
	}
	return errors.Join(errs...)
}

func (rp *ReadPath) checkCheckpoint(name, origin string, verifier *torchwood.CosignatureVerifier, maxAge time.Duration) error {
	signedCheckpoint, err := fs.ReadFile(rp.files, name)
	if err != nil {
		return fmt.Errorf("failed to read checkpoint: %w", err)
	}
	n, err := note.Open(signedCheckpoint, note.VerifierList(verifier))
	if err != nil {
		return fmt.Errorf("failed to verify checkpoint: %w", err)
	}
	checkpoint, err := torchwood.ParseCheckpoint(n.Text)
	if err != nil {
		return fmt.Errorf("failed to parse checkpoint: %w", err)
	}
	if checkpoint.Origin != origin {
		return fmt.Errorf("origin mismatch: %q != %q", checkpoint.Origin, origin)
	}
	t, err := torchwood.CosignatureTimestamp(n.Sigs[0])
	if err != nil {
		return fmt.Errorf("failed to parse signature timestamp: %w", err)
	}
	if ct := time.Unix(t, 0); time.Since(ct) > maxAge {
		return fmt.Errorf("checkpoint is too old: %v", ct)
	}
	return nil
}
