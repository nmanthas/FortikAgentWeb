package action

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestValidate(t *testing.T) {
	ok := Action{AgentID: "finance_agent_07", System: "gmail", Verb: VerbSend}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid action rejected: %v", err)
	}
	cases := map[string]Action{
		"no agent":       {System: "gmail", Verb: VerbSend},
		"bad agent":      {AgentID: "a b", System: "gmail", Verb: VerbSend},
		"no system":      {AgentID: "a", Verb: VerbSend},
		"bad system":     {AgentID: "a", System: "Gmail!", Verb: VerbSend},
		"no verb":        {AgentID: "a", System: "gmail"},
		"negative cost":  {AgentID: "a", System: "aws", Verb: VerbSpend, EstCostUSD: -1},
		"bad instance":   {AgentID: "a", System: "aws", Verb: VerbRead, InstanceID: "../x"},
		"chain too long": {AgentID: "a", System: "aws", Verb: VerbRead, Chain: make([]string, 65)},
		"agent too long": {AgentID: strings.Repeat("a", 129), System: "aws", Verb: VerbRead},
		"bad action id":  {ActionID: "act 1", AgentID: "a", System: "aws", Verb: VerbRead},
	}
	for name, a := range cases {
		if err := a.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
	// An unknown verb is structurally valid: policy fails it closed (POL-002).
	unk := Action{AgentID: "a", System: "gmail", Verb: "FROBNICATE"}
	if err := unk.Validate(); err != nil {
		t.Fatalf("unknown verb must reach policy, got %v", err)
	}
}

func TestNormalize(t *testing.T) {
	client := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	a := Action{AgentID: "a", System: "gmail", Verb: "send", TS: client, Target: map[string]any{},
		PayloadSummary: PayloadSummary{DataLabels: []string{"Customer_PII", " customer_pii", "financial", ""}}}
	a.Normalize(now)
	if !strings.HasPrefix(a.ActionID, "act_") || a.Verb != VerbSend || !a.TS.Equal(now) {
		t.Fatalf("normalize: %+v", a)
	}
	if a.Target["client_ts"] != client.Format(time.RFC3339Nano) {
		t.Fatal("client ts not preserved for forensics")
	}
	if got := strings.Join(a.PayloadSummary.DataLabels, ","); got != "customer_pii,financial" {
		t.Fatalf("labels: %s", got)
	}
	var b Action
	b.AgentID, b.System, b.Verb = "a", "x", VerbRead
	b.Normalize(now)
	if b.Target == nil {
		t.Fatal("nil target must become empty map")
	}
}

func TestHashStableAndIgnoresClientTS(t *testing.T) {
	a := Action{System: "gmail", Verb: VerbSend, Target: map[string]any{"to": []string{"x@y.com"}, "client_ts": "1"}}
	b := Action{System: "gmail", Verb: VerbSend, Target: map[string]any{"client_ts": "2", "to": []string{"x@y.com"}}}
	if a.Hash() != b.Hash() {
		t.Fatal("hash must ignore client_ts and key order")
	}
	c := Action{System: "gmail", Verb: VerbSend, Target: map[string]any{"to": []string{"z@y.com"}}}
	if a.Hash() == c.Hash() {
		t.Fatal("different targets must hash differently")
	}
}

func TestKnownVerbs(t *testing.T) {
	if len(Verbs()) != 10 || !KnownVerb(VerbRemember) || KnownVerb("PATCH") {
		t.Fatal("verb set wrong")
	}
}

// Phase 5 review: the Max-5 breaker's identity of a Gmail SEND is who
// receives it, so recipient order, To/Cc/Bcc placement, +tags, drafts.send
// (unique draft ids) and users/<own address> do not make a "new" call.
func TestGmailSendHashIsRecipientIdentity(t *testing.T) {
	send := func(target map[string]any) string {
		a := Action{System: SystemGmail, Verb: VerbSend, Target: target}
		return a.Hash()
	}
	base := send(map[string]any{"endpoint": "gmail.users.messages.send", "user_id": "me",
		"to": []any{"v1@x.com", "v2@x.com"}, "cc": []any{}, "bcc": []any{}, "external_domains": 1, "attachment_bytes": 0})
	for name, tgt := range map[string]map[string]any{
		"reordered": {"endpoint": "gmail.users.messages.send", "user_id": "me",
			"to": []any{"v2@x.com", "v1@x.com"}, "cc": []any{}, "bcc": []any{}, "external_domains": 1, "attachment_bytes": 0},
		"moved to cc": {"endpoint": "gmail.users.messages.send", "user_id": "me",
			"to": []any{"v1@x.com"}, "cc": []any{"V2@X.com"}, "bcc": []any{}, "external_domains": 1, "attachment_bytes": 0},
		"draft": {"endpoint": "gmail.users.drafts.send", "user_id": "me", "draft_id": "r111",
			"to": []any{"v1+a@x.com"}, "cc": []any{}, "bcc": []any{"v2@x.com"}, "external_domains": 1, "attachment_bytes": 0},
		"own address": {"endpoint": "gmail.users.messages.send", "user_id": "agent@acme.com",
			"to": []string{"v1@x.com", "v2@x.com", "v1@x.com"}, "external_domains": 1, "attachment_bytes": 0},
	} {
		if h := send(tgt); h != base {
			t.Errorf("%s: hash differs", name)
		}
	}
	if send(map[string]any{"to": []any{"v1@x.com", "v3@x.com"}, "external_domains": 1, "attachment_bytes": 0}) == base {
		t.Error("different recipients share a hash")
	}
	if send(map[string]any{"to": []any{"v1@x.com", "v2@x.com"}, "external_domains": 1, "attachment_bytes": 9}) == base {
		t.Error("an attachment does not change the hash")
	}
	// Other systems keep the full target.
	d1 := Action{System: SystemDrive, Verb: VerbSend, Target: map[string]any{"to": []any{"a"}, "draft_id": "1"}}
	d2 := Action{System: SystemDrive, Verb: VerbSend, Target: map[string]any{"to": []any{"a"}, "draft_id": "2"}}
	if d1.Hash() == d2.Hash() {
		t.Error("non-gmail target canonicalised")
	}
}
