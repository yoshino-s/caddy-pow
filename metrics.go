package caddy_pow

import (
	"math"

	"github.com/caddyserver/caddy/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type Metrics struct {
	bypasses            prometheus.Counter
	challengesIssued    prometheus.Counter
	challengesValidated prometheus.Counter
	failedValidations   prometheus.Counter
	timeTaken           prometheus.Histogram
}

func (m *Middleware) registerMetrics(ctx caddy.Context) {
	registry := ctx.GetMetricsRegistry()

	m.metrics.bypasses = promauto.With(registry).NewCounter(prometheus.CounterOpts{
		Name: "anubis_bypasses",
		Help: "The total number of requests that bypassed challenge validation",
	})

	m.metrics.challengesIssued = promauto.With(registry).NewCounter(prometheus.CounterOpts{
		Name: "anubis_challenges_issued",
		Help: "The total number of challenges issued",
	})

	m.metrics.challengesValidated = promauto.With(registry).NewCounter(prometheus.CounterOpts{
		Name: "anubis_challenges_validated",
		Help: "The total number of challenges validated",
	})

	m.metrics.failedValidations = promauto.With(registry).NewCounter(prometheus.CounterOpts{
		Name: "anubis_failed_validations",
		Help: "The total number of failed validations",
	})

	m.metrics.timeTaken = promauto.With(registry).NewHistogram(prometheus.HistogramOpts{
		Name:    "anubis_time_taken",
		Help:    "The time taken for a browser to generate a response (milliseconds)",
		Buckets: prometheus.ExponentialBucketsRange(1, math.Pow(2, 18), 19),
	})
}
