package main

import (
	"slices"
	"strings"
	"time"

	ht "github.com/filippo-claude/hetrixtools-sync"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

func main() {
	ht.Main(definitions)
}

func definitions(h *ht.Hetrix) {
	h.WebsiteDefaults(ht.Website{
		Locations:            []string{"new_york", "san_francisco", "amsterdam", "london", "tokyo"},
		Method:               "GET",
		AcceptedHTTPStatuses: []int{200},
		Timeout:              10 * time.Second,
		Frequency:            time.Minute,
		Tries:                3,
		TriggeringLocations:  3,
		RepeatTimes:          3,
		RepeatEvery:          20 * time.Minute,
		MaxRedirects:         5,
	})
	h.CronDefaults(ht.Cron{Interval: 15 * time.Minute})

	h.IgnoreExisting(func(m ht.ExistingMonitor) bool {
		return !slices.Contains(m.ContactLists, "CT log") &&
			!slices.Contains(m.ContactLists, "CT staging")
	})

	status := h.StatusPage(ht.StatusPage{Name: "Geomys Trust and Transparency Services"})

	he := hetrixEnv{
		ProdWebsite: func(m ht.Website) {
			m.ContactList = "CT log"
			m.Public = true
			if strings.HasPrefix(m.Target, "https://uptime.geomys.org/") {
				m.AlertAfter = 5 * time.Minute
				m.TriggeringLocations = 5
			}
			ref := h.Website(m)
			status.Add(ref)
		},
		StagingWebsite: func(m ht.Website) {
			m.ContactList = "CT staging"
			if strings.HasPrefix(m.Target, "https://uptime.geomys.org/") {
				m.AlertAfter = 5 * time.Minute
				m.TriggeringLocations = 5
			}
			h.Website(m)
		},
		Cron: func(m ht.Cron) {
			m.ContactList = "CT staging"
			h.Cron(m)
		},
	}

	node(he, "tuscolo", "navigli")
	node(he, "trastevere", "loreto")

	he.ProdWebsite(ht.Website{
		Name:     "endpoint_uptime_24h.csv",
		Target:   "https://uptime.geomys.org/ct/24h/geomys.org",
		Category: "General",
	})

	he.StagingWebsite(ht.Website{
		Name:    "witness.navigli.sunlight.geomys.org add-checkpoint",
		Target:  "https://uptime.geomys.org/witness/add-checkpoint/witness.navigli.sunlight.geomys.org+a3e00fe2+BNy/co4C1Hn1p+INwJrfUlgz7W55dSZReusH/GhUhJ/G",
		Keyword: "witness signature valid",
	})

	he.ProdWebsite(ht.Website{
		Name:     "witness-golf.sunlight.geomys.org",
		Target:   "https://witness-golf.sunlight.geomys.org/health",
		Category: "Witness",
	})
	he.ProdWebsite(ht.Website{
		Name:     "witness-golf.sunlight.geomys.org add-checkpoint",
		Target:   "https://uptime.geomys.org/witness/add-checkpoint/witness-golf.sunlight.geomys.org+285a8d9f",
		Keyword:  "witness signature valid",
		Category: "Witness",
	})
}

type hetrixEnv struct {
	ProdWebsite    func(ht.Website)
	StagingWebsite func(ht.Website)
	Cron           func(ht.Cron)
}

func node(h hetrixEnv, prod, staging string) {
	// Trastevere's network is too unstable to page prod in < 3 minutes.
	if prod == "trastevere" {
		prodWebsite := h.ProdWebsite
		h.ProdWebsite = func(m ht.Website) {
			m.AlertAfter = 3 * time.Minute
			prodWebsite(m)
		}
	}

	h.ProdWebsite(ht.Website{
		Name:     prod + ".sunlight.geomys.org",
		Target:   "https://" + prod + ".sunlight.geomys.org/health",
		Category: cases.Title(language.English).String(prod),
	})
	h.ProdWebsite(ht.Website{
		Name:     prod + ".skylight.geomys.org",
		Target:   "https://" + prod + ".skylight.geomys.org/health",
		Category: cases.Title(language.English).String(prod),
	})
	h.StagingWebsite(ht.Website{
		Name:   staging + ".sunlight.geomys.org",
		Target: "https://" + staging + ".sunlight.geomys.org/health",
	})

	h.ProdWebsite(ht.Website{
		Name:     prod + ".skylight.geomys.org logs.json",
		Target:   "https://" + prod + ".skylight.geomys.org/logs.json",
		Keyword:  "Geomys",
		Category: cases.Title(language.English).String(prod),
	})

	h.Cron(ht.Cron{
		Name: prod + " partial-aftersun",
	})
	h.Cron(ht.Cron{
		Name: staging + " partial-aftersun",
	})

	h.Cron(ht.Cron{
		Name:     prod + " heliograph-dashboard",
		Interval: 5 * time.Minute,
		Grace:    15 * time.Minute,
	})

	for _, shard := range []string{
		"2026h2",
		"2027h1",
		"2027h2",
		"2028h1",
		"2028h2",
	} {
		h.ProdWebsite(ht.Website{
			Name: prod + shard + ".sunlight.geomys.org",
			Target: "https://uptime.geomys.org/ct/add-pre-chain/" +
				prod + shard + ".sunlight.geomys.org",
			Keyword:  "SCT verified and included",
			Category: cases.Title(language.English).String(prod) + " shards",
		})

		h.StagingWebsite(ht.Website{
			Name: staging + shard + ".sunlight.geomys.org",
			Target: "https://uptime.geomys.org/ct/add-pre-chain/" +
				staging + shard + ".sunlight.geomys.org",
			Keyword: "SCT verified and included",
		})
	}
}
