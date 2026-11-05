package containment_test

import (
	"encoding/json"
	"testing"

	"fortik/internal/containment"
)

func receiptOf(t *testing.T, e *env, opID string) containment.Receipt {
	t.Helper()
	r := call(t, e.api, auditor, "GET", "/v1/containment/"+opID+"/receipt", "")
	if r.code != 200 {
		t.Fatalf("receipt: %d %s", r.code, r.raw)
	}
	var rc containment.Receipt
	if err := json.Unmarshal([]byte(r.raw), &rc); err != nil {
		t.Fatal(err)
	}
	return rc
}

func checkOf(rc containment.Receipt, name string) containment.ReceiptCheck {
	for _, c := range rc.Checks {
		if c.Name == name {
			return c
		}
	}
	return containment.ReceiptCheck{}
}

// A kill whose effects hold is confirmed by re-reading state, not by the
// steps' own reports; later drift (the level changed back) makes the same
// receipt fail; a failed revocation is never "confirmed".
func TestReceiptVerifiesStateNotReports(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.agent(t, "a1", "payments", "jane@acme.com", 2)
	e.register(t, "a1", "a1-i1")
	op := opOf(t, e.post(t, security, "/v1/agents/a1/kill", `{"reason":"exfiltration confirmed"}`))

	rc := receiptOf(t, e, op.OpID)
	if rc.Outcome != containment.OutcomeConfirmed {
		t.Fatalf("kill receipt: %s %s %+v residual=%v", rc.Outcome, rc.Summary, rc.Checks, rc.Residual)
	}
	if c := checkOf(rc, "level"); !c.Primary || c.Outcome != containment.CheckConfirmed || c.Observed != "KILLED" {
		t.Fatalf("level check: %+v", c)
	}
	if c := checkOf(rc, "running_copies"); c.Outcome != containment.CheckConfirmed {
		t.Fatalf("copies check: %+v", c)
	}
	if len(rc.DiarySeqs) == 0 {
		t.Fatal("receipt not linked to the Diary")
	}

	// Drift: someone set the level back. The receipt now says so.
	if _, err := e.pool.Exec(t.Context(), `UPDATE agents SET level = 0 WHERE agent_id = 'a1'`); err != nil {
		t.Fatal(err)
	}
	if rc := receiptOf(t, e, op.OpID); rc.Outcome != containment.OutcomeFailed || checkOf(rc, "level").Outcome != containment.CheckFailed {
		t.Fatalf("after drift: %s %+v", rc.Outcome, checkOf(rc, "level"))
	}

	// A kill whose revocation failed: the level holds, the result is partial.
	e.agent(t, "a2", "payments", "jane@acme.com", 2)
	e.rev.setFail("a2", true)
	op2 := opOf(t, e.post(t, security, "/v1/agents/a2/kill", `{"reason":"compromised"}`))
	if rc := receiptOf(t, e, op2.OpID); rc.Outcome != containment.OutcomePartial {
		t.Fatalf("failed revocation: %s %s", rc.Outcome, rc.Summary)
	}

	// Unknown operation id.
	if r := call(t, e.api, auditor, "GET", "/v1/containment/cop_nope/receipt", ""); r.code != 404 {
		t.Fatalf("unknown op: %d", r.code)
	}
	// Owners cannot read receipts (auditor or security only).
	if r := call(t, e.api, jane, "GET", "/v1/containment/"+op.OpID+"/receipt", ""); r.code != 403 {
		t.Fatalf("owner: %d", r.code)
	}
}

// Suspend and resume: the receipt re-reads suspended_at.
func TestReceiptSuspendResume(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.agent(t, "s1", "support", "jane@acme.com", 2)
	op := opOf(t, e.post(t, security, "/v1/agents/s1/suspend", `{"reason":"odd refunds"}`))
	if rc := receiptOf(t, e, op.OpID); checkOf(rc, "suspended").Outcome != containment.CheckConfirmed {
		t.Fatalf("suspend receipt: %+v", rc.Checks)
	}
	res := opOf(t, e.post(t, security, "/v1/agents/s1/resume", `{"reason":"false alarm"}`))
	if rc := receiptOf(t, e, res.OpID); rc.Outcome != containment.OutcomeConfirmed {
		t.Fatalf("resume receipt: %s %s", rc.Outcome, rc.Summary)
	}
	// The suspend's receipt now shows the agent is no longer suspended.
	if rc := receiptOf(t, e, op.OpID); rc.Outcome != containment.OutcomeFailed {
		t.Fatalf("suspend receipt after resume: %s", rc.Outcome)
	}
}
