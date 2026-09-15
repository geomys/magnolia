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
		ProdCron: func(m ht.Cron) {
			m.ContactList = "CT log"
			m.Public = true
			ref := h.Cron(m)
			status.Add(ref)
		},
		StagingCron: func(m ht.Cron) {
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
	// TODO: URL is too long.
	// he.ProdWebsite(ht.Website{
	// 	Name:     "witness-golf.sunlight.geomys.org add-checkpoint",
	// 	Target:   "https://uptime.geomys.org/witness/add-checkpoint/witness-golf.sunlight.geomys.org+285a8d9f+BmXb1ItjzDOpqzbdlBDvu5HD+lM3cZMMdPpnBsskhj99lnA4KDncLD5ck/YXkOgNjani4pFnX4PFKtM5WefU/+3TQv4qyOpXtUVLsExml5qdmiqwaMYb7Oz8WPntgJ+PWLECCOQWhMdgvj50O2MdbaSHZI74MrE2ARVcxalUf16awdvwZD8qLVgZATxMP56NtEmbRmRIHrakSzHLL93iM1RElqjoBW7njk6sBgUpHrY6ljMXRvrL2rLBlZj7zZ6pz6NoKR5fYhw63YAPLTBwf4m2YarWtcPZ7gNHN/4n9I5LheySxcu47cKsOdzKCIsa9+sXbZUEbKW1CBu8Tl3nd/MuPKC/5F3zccaUFURZlqgnS1PKOqeCc1xuXnnUOmulYJbMPosYMmSuxqbuO56q+haO4ZsYYlBeeslN73EoKW2iF7CDxtQCWwBrnKn2WZxf5/3EVTweL4kYXZ+G4DmJkfGHlyUJj/dJRi0V1rj/F8sFLwZNRc/LoNBqhY+CJw5+KdItNVBM3RTNQFoGwAa9oTFAIfBJA2qjlJQ1L1NxxfD1G6MwUvOkDeZpghyVU1fDiyeKdsfxtWBlOeJYd64v2el/Z2CqegQaiWTw5rbWz7EPxNs0f/z2Qg7V8x9warJW7o0ta1YR4MvIUKJy2aIy3kE/94qBF2ai95j9wkazIPxZJjBVjKz+mHGsRw5yH6zC22xD4NLulD9IBWGsbpPL5WGLfVdcYyjelLLdFcwNogAwr25bQHRrW51WCdfxfJp0XubgaXKhV92LyQ5YEwe7YDMi+aOZBaI73Y6Tg7oxsXRTyUBUR6vU0vtkfrWI1PkI35sdK7bDBbZNsPQ0tbtM4MhJIcwUzv8sPnrZMpu7w+LVgvAxhIbd49ITjRz0JA8NomcHX0zCvES/hVtAZmQoH2K4cYTrCX9wbg9jx9Vz02cX5szL6UIf6W0fOI4h8cjTsI1lw/U9rDJxmIfVIatkvLkmJHqzOBfDFe7nY7ASrnMTqr3Ei08eiRVvLgLkqgWyekb1x4GnaOE1OrumCrP1b9dPDQF9XUPZWHRqq4S0lhlGVs0FnykXTRxxF0tF2NrR+66J9z4HFX5PX+4MiwmX/E0Bs6TM8Yr2/loVF4ipzXsKkDI1wfid5i8Xx3PRBtbhFUQ87Oytjyu5L1cdXbhy/iDFBUN5bJ2WEubbKm6f35NAuXdW355B2p6iksgqacARu25vTHDIL26AVT80J18CrJ0Loq1Q3IYIPGWSlS5Eg2mOM2M4JGIPPJEv0+QJ/t+y5+hrjlJNiDbdwtJIUIMv/Gk+NQb2arRahhDzrraqG7VK7yme6B3u3CeNwyrgrfbQXSE4Ikq8HevZcUKuwHWJmeHdjxB1fDVWzDYJoXzLxiXL95iE9esi65I/eFaeL43Rw6Uxu0draErdZTuLnMbRKDw0U4rab5oJIf/AboJmeu7xLCAXP0I9c++S8Ko0djwdsJHRovP9pbRA0zC/Q1Km9gaG5tuzmn+CAH0FuK0Egpx6sIXNpC/hMFDz2Oq/F6mqtxel6DYDfoA6Eim3jqfjtDQfrpCPVrbiA4Cj/zuI2Alb5EJDnWWXY8eunVAJz+P9h0F4ththRna1mvpmh7k00R7UzKfcZdClh9nE65T21RUloSfwV6k/A3Gz7+uUKMr8f6tjfi66DOSxZAsquwG7yoiaGxY7dP3o8bZeXQLcXq3bvO9/LtS6PshWNi/WQX40rAWLTKU1XbjtibbqwudbB6k=",
	// 	Keyword:  "witness signature valid",
	// 	Category: "Witness",
	// })
}

type hetrixEnv struct {
	ProdWebsite, StagingWebsite func(ht.Website)
	ProdCron, StagingCron       func(ht.Cron)
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

	h.ProdCron(ht.Cron{
		Name:     prod + " partial-aftersun",
		Category: cases.Title(language.English).String(prod),
	})
	h.StagingCron(ht.Cron{
		Name: staging + " partial-aftersun",
	})

	h.StagingCron(ht.Cron{
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
