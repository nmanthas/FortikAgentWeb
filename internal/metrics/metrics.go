// Package metrics exposes Prometheus metrics. Labels carry classes, systems
// and rule ids only — never payloads, SQL, recipients or agent secrets.
package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	Registry = prometheus.NewRegistry()

	Decisions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "fortik_decisions_total", Help: "Actions decided, by class/decision/system/source.",
	}, []string{"class", "decision", "system", "source"})

	DecideLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "fortik_decide_latency_seconds",
		Help:    "Fortik decision overhead (control state + policy + persistence), excluding downstream systems.",
		Buckets: []float64{.0005, .001, .002, .005, .01, .02, .05, .1, .25, .5, 1},
	}, []string{"class"})

	PolicyEval = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "fortik_policy_eval_seconds",
		Help:    "OPA evaluation time.",
		Buckets: []float64{.0001, .00025, .0005, .001, .002, .005, .01, .025},
	})

	FailClosed = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "fortik_fail_closed_total", Help: "Decisions produced by the fail-closed path, by stage.",
	}, []string{"stage", "outcome"})

	StepDowns = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "fortik_step_downs_total", Help: "Automatic ladder step-downs, by target level and rule.",
	}, []string{"to", "rule_id"})

	Held = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "fortik_held_actions_total", Help: "Actions placed in held_actions, by class and rule.",
	}, []string{"class", "rule_id"})

	UndoRuns = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "fortik_undo_total", Help: "Undo executions, by kind and outcome.",
	}, []string{"kind", "outcome"})

	PolicyReloads = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "fortik_policy_reloads_total", Help: "Policy bundle reload attempts.",
	}, []string{"outcome"})
)

func init() {
	Registry.MustRegister(Decisions, DecideLatency, PolicyEval, FailClosed, StepDowns, Held, UndoRuns, PolicyReloads,
		prometheus.NewGoCollector(), prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
}
