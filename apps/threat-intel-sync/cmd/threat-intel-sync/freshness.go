package main

import (
	"sort"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// fresh computes, at scrape time, whether each source is within its
// freshness objective (SOURCE_MAX_AGE): threat_intel_source_stale{source}
// is 1 once the last success is older than the objective, or there has
// never been one. A gauge set by the sync loop would only change when the
// loop runs, and a source that stops answering is exactly the case where it
// may not run for hours. The alert can use this series, or compare
// threat_intel_source_last_success_timestamp_seconds with
// threat_intel_source_freshness_objective_seconds itself.
var fresh = &freshnessCollector{now: time.Now}

var staleDesc = prometheus.NewDesc("threat_intel_source_stale",
	"1 if the source's last success is older than its freshness objective (or it never succeeded), 0 otherwise.",
	[]string{"source"}, nil)

type freshnessCollector struct {
	mu         sync.RWMutex
	objectives map[string]time.Duration
	last       func() map[string]time.Time
	now        func() time.Time
}

// configure sets the objectives and where last successes are read from
// (the store's record, which survives restarts).
func (c *freshnessCollector) configure(objectives map[string]time.Duration, last func() map[string]time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.objectives = make(map[string]time.Duration, len(objectives))
	for k, v := range objectives {
		c.objectives[k] = v
	}
	c.last = last
}

// sourceFreshness is one source's state for /readyz.
type sourceFreshness struct {
	LastSuccess *time.Time `json:"last_success"`
	AgeSeconds  *int64     `json:"age_seconds"`
	Objective   int64      `json:"freshness_objective_seconds"`
	Stale       bool       `json:"stale"`
}

func (c *freshnessCollector) status() map[string]sourceFreshness {
	c.mu.RLock()
	objectives, lastFn, now := c.objectives, c.last, c.now()
	c.mu.RUnlock()
	var last map[string]time.Time
	if lastFn != nil {
		last = lastFn()
	}
	out := make(map[string]sourceFreshness, len(objectives))
	for name, obj := range objectives {
		f := sourceFreshness{Objective: int64(obj.Seconds()), Stale: true}
		if t, ok := last[name]; ok && !t.IsZero() {
			t := t.UTC()
			age := int64(now.Sub(t).Seconds())
			f.LastSuccess, f.AgeSeconds = &t, &age
			f.Stale = now.Sub(t) > obj
		}
		out[name] = f
	}
	return out
}

// stale returns the stale sources, sorted.
func (c *freshnessCollector) stale() []string {
	var out []string
	for name, f := range c.status() {
		if f.Stale {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func (c *freshnessCollector) Describe(ch chan<- *prometheus.Desc) { ch <- staleDesc }

func (c *freshnessCollector) Collect(ch chan<- prometheus.Metric) {
	for name, f := range c.status() {
		v := 0.0
		if f.Stale {
			v = 1
		}
		ch <- prometheus.MustNewConstMetric(staleDesc, prometheus.GaugeValue, v, name)
	}
}
