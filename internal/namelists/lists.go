package namelists

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"geomys.org/magnolia/internal/durable"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	// refreshInterval is how often each list is fetched. The Public Suffix
	// List asks not to be downloaded more than once per day.
	refreshInterval = 24 * time.Hour

	// retryInterval is how long to wait after a failed fetch.
	retryInterval = 5 * time.Minute

	// maxAge is how long a list is used for after it was last fetched.
	maxAge = 30 * 24 * time.Hour

	// maxSize is the maximum size of a list. The largest, the Public Suffix
	// List, is about 350 kB.
	maxSize = 8 << 20 // 8 MB
)

type list int

const (
	tldList list = iota
	suffixList
	ipv4List
	ipv6List
	numLists
)

var sources = [numLists]struct {
	name        string // in logs and metrics
	description string // in errors
	file        string // in the cache directory
	url         string
	// check reports whether data can replace the current version of the
	// list, to keep a truncated or mistaken response from doing so.
	check func(data []byte) error
}{
	tldList: {
		name: "tlds", description: "list of top-level domains",
		file: "tlds-alpha-by-domain.txt",
		url:  "https://data.iana.org/TLD/tlds-alpha-by-domain.txt",
		check: func(data []byte) error {
			t, err := ParseTLDs(data)
			if err != nil {
				return err
			}
			if len(t.names) < 1000 || !t.Contains("com") {
				return errors.New("implausible list of top-level domains")
			}
			return nil
		},
	},
	suffixList: {
		name: "public_suffixes", description: "Public Suffix List",
		file: "public_suffix_list.dat",
		url:  "https://publicsuffix.org/list/public_suffix_list.dat",
		check: func(data []byte) error {
			p, err := ParsePublicSuffixes(data)
			if err != nil {
				return err
			}
			if len(p.rules) < 5000 || !p.Contains("com") || !p.Contains("co.uk") {
				return errors.New("implausible Public Suffix List")
			}
			return nil
		},
	},
	ipv4List: {
		name: "ipv4_special_purpose", description: "IPv4 special-purpose address registry",
		file: "iana-ipv4-special-registry-1.csv",
		url:  "https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry-1.csv",
		check: func(data []byte) error {
			return checkAddressRegistry(data, "10.0.0.0/8", "127.0.0.0/8",
				"172.16.0.0/12", "192.168.0.0/16", "240.0.0.0/4", "255.255.255.255/32")
		},
	},
	ipv6List: {
		name: "ipv6_special_purpose", description: "IPv6 special-purpose address registry",
		file: "iana-ipv6-special-registry-1.csv",
		url:  "https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry-1.csv",
		check: func(data []byte) error {
			return checkAddressRegistry(data, "::1/128", "fc00::/7", "fe80::/10")
		},
	},
}

// checkAddressRegistry checks that data is a registry of blocks of the same
// family as the expected ones, which it includes. Both registries have more
// than 20 distinct blocks. The expected blocks include long-standing entries
// near the end of each registry, to detect truncated responses.
func checkAddressRegistry(data []byte, expected ...string) error {
	blocks, err := parseAddressRegistry(data)
	if err != nil {
		return err
	}
	found := make(map[netip.Prefix]bool)
	for _, b := range blocks {
		found[b] = true
	}
	if len(found) < 20 {
		return errors.New("implausible special-purpose address registry")
	}
	for _, e := range expected {
		want := netip.MustParsePrefix(e)
		if !found[want] {
			return fmt.Errorf("implausible special-purpose address registry: missing %v", want)
		}
		for b := range found {
			if b.Addr().Is4() != want.Addr().Is4() {
				return fmt.Errorf("address block %v is in the wrong registry", b)
			}
		}
	}
	return nil
}

// Lists holds the current version of each list.
//
// Lists made by [Open] are fetched over HTTPS by [Lists.Run] every day, and are
// cached on disk, so restarts don't depend on the network.
//
// Lists must be constructed with [Open] or [Static] and must not be copied. It
// is safe for concurrent use, except that only one call to [Lists.Run] may be
// active at a time.
type Lists struct {
	static bool
	dir    string
	client *http.Client
	logger *slog.Logger

	fetchTime   *prometheus.GaugeVec
	fetchErrors *prometheus.CounterVec

	mu       sync.RWMutex
	data     [numLists][]byte
	fetched  [numLists]time.Time
	tlds     *TLDs
	suffixes *PublicSuffixes
	reserved *ReservedIPs
}

// Static returns Lists that never change or expire. A nil list is unavailable.
func Static(tlds *TLDs, suffixes *PublicSuffixes, reserved *ReservedIPs) *Lists {
	l := &Lists{static: true, tlds: tlds, suffixes: suffixes, reserved: reserved}
	now := time.Now()
	if tlds != nil {
		l.fetched[tldList] = now
	}
	if suffixes != nil {
		l.fetched[suffixList] = now
	}
	if reserved != nil {
		l.fetched[ipv4List], l.fetched[ipv6List] = now, now
	}
	return l
}

type Config struct {
	// Dir is the path to the directory where the lists are cached.
	// It will be created if it doesn't already exist.
	Dir string

	// Client is the HTTP client used to fetch the lists.
	// If nil, a client with a 30-second timeout is used.
	Client *http.Client

	Logger *slog.Logger
}

// Open loads the lists cached in Config.Dir. The lists that are not there
// are unavailable until [Lists.Run] fetches them.
func Open(c Config) (*Lists, error) {
	if c.Dir == "" {
		return nil, errors.New("missing Dir")
	}
	if err := durable.MkdirAll(c.Dir, 0o755); err != nil {
		return nil, err
	}
	l := &Lists{
		dir:    c.Dir,
		client: c.Client,
		logger: c.Logger,
		fetchTime: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "namelists_fetch_timestamp_seconds",
			Help: "Unix time each list was last fetched successfully.",
		}, []string{"list"}),
		fetchErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "namelists_fetch_errors_total",
			Help: "Number of failed attempts to fetch each list.",
		}, []string{"list"}),
	}
	if l.client == nil {
		l.client = &http.Client{Timeout: 30 * time.Second}
	}
	client := *l.client
	checkRedirect := client.CheckRedirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" {
			return fmt.Errorf("refusing redirect to non-HTTPS URL %q", req.URL)
		}
		if checkRedirect != nil {
			return checkRedirect(req, via)
		}
		// Preserve the default http.Client redirect limit.
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}
	l.client = &client
	if l.logger == nil {
		l.logger = slog.New(slog.DiscardHandler)
	}
	for i, source := range sources {
		l.fetchErrors.WithLabelValues(source.name)
		path := filepath.Join(l.dir, source.file)
		data, err := os.ReadFile(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		// Only checked lists are cached, so this is corruption.
		if err := source.check(data); err != nil {
			l.logger.Error("ignoring invalid cached list", "list", source.name, "path", path, "err", err)
			continue
		}
		l.set(list(i), data, info.ModTime())
	}
	return l, nil
}

// set replaces a list with data, which must have passed its check.
func (l *Lists) set(i list, data []byte, fetched time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.data[i] = data
	l.fetched[i] = fetched
	l.fetchTime.WithLabelValues(sources[i].name).Set(float64(fetched.Unix()))
	switch i {
	case tldList:
		l.tlds, _ = ParseTLDs(data)
	case suffixList:
		l.suffixes, _ = ParsePublicSuffixes(data)
	case ipv4List, ipv6List:
		if l.data[ipv4List] != nil && l.data[ipv6List] != nil {
			l.reserved, _ = ParseReservedIPs(l.data[ipv4List], l.data[ipv6List])
		}
	}
}

// Metrics returns the metrics to register for the lists.
func (l *Lists) Metrics() []prometheus.Collector {
	if l.static {
		return nil
	}
	return []prometheus.Collector{l.fetchTime, l.fetchErrors}
}

// DNS returns the lists needed to check a DNS name.
// It returns an error if either is unavailable or stale.
func (l *Lists) DNS() (*TLDs, *PublicSuffixes, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if err := l.available(tldList, suffixList); err != nil {
		return nil, nil, err
	}
	return l.tlds, l.suffixes, nil
}

// IP returns the list needed to check an IP address.
// It returns an error if either of the registries is unavailable or stale.
func (l *Lists) IP() (*ReservedIPs, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if err := l.available(ipv4List, ipv6List); err != nil {
		return nil, err
	}
	return l.reserved, nil
}

func (l *Lists) available(lists ...list) error {
	for _, i := range lists {
		switch {
		case l.fetched[i].IsZero():
			return fmt.Errorf("the %s has not been fetched yet", sources[i].description)
		case !l.static && time.Since(l.fetched[i]) > maxAge:
			return fmt.Errorf("the %s was last fetched on %s, more than %d days ago",
				sources[i].description, l.fetched[i].UTC().Format(time.DateOnly), maxAge/(24*time.Hour))
		}
	}
	return nil
}

// Run fetches the lists that are missing, and then every list once a day,
// until ctx is canceled. Failures are logged and retried.
// Only one call to Run may be active at a time for a given Lists.
func (l *Lists) Run(ctx context.Context) error {
	if l.static {
		<-ctx.Done()
		return ctx.Err()
	}
	for {
		wait := l.refresh(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

// refresh fetches the lists that are due, and returns how long to wait before
// calling it again.
func (l *Lists) refresh(ctx context.Context) time.Duration {
	wait := refreshInterval
	for i, source := range sources {
		l.mu.RLock()
		fetched := l.fetched[i]
		l.mu.RUnlock()
		if age := time.Since(fetched); !fetched.IsZero() && age < refreshInterval {
			wait = min(wait, refreshInterval-max(age, 0))
			continue
		}
		if err := l.fetch(ctx, list(i)); err != nil {
			if ctx.Err() != nil {
				return wait
			}
			l.fetchErrors.WithLabelValues(source.name).Inc()
			l.logger.Error("failed to fetch list", "list", source.name, "url", source.url,
				"last_fetched", fetched, "err", err)
			wait = min(wait, retryInterval)
			continue
		}
		l.logger.Info("fetched list", "list", source.name, "url", source.url)
	}
	return wait
}

func (l *Lists) fetch(ctx context.Context, i list) error {
	source := sources[i]
	req, err := http.NewRequestWithContext(ctx, "GET", source.url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "geomys.org/magnolia")
	resp, err := l.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %q", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxSize+1))
	if err != nil {
		return err
	}
	if len(data) > maxSize {
		return fmt.Errorf("response is larger than %d bytes", maxSize)
	}
	if err := source.check(data); err != nil {
		return err
	}

	// The modification time records when the list was fetched. It is set
	// explicitly so that it comes from the same clock it is compared with.
	path := filepath.Join(l.dir, source.file)
	now := time.Now()
	if err := durable.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	if err := os.Chtimes(path, now, now); err != nil {
		return err
	}
	l.set(i, data, now)
	return nil
}
