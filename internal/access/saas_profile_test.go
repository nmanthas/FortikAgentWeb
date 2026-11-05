package access

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSaaSProfileAgentforceKeys(t *testing.T) {
	ok := []string{
		`{"mode":"read_write","objects":["*"],"agentforce_agents":["0Xxg70000020uCOCAY"]}`,
		`{"mode":"read_write","objects":["*"],"agentforce_agents":["*"],"agentforce_messages":"allow"}`,
		`{"mode":"read_only","objects":["account"],"agentforce_agents":["0Xxg70000020uCO"],"agentforce_messages":"approval"}`,
	}
	for _, p := range ok {
		if _, err := Validate("salesforce", json.RawMessage(p)); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
	}
	bad := map[string]string{
		`{"mode":"read_write","objects":["*"],"agentforce_agents":["not-an-id"]}`:                "agentforce_agents",
		`{"mode":"read_write","objects":["*"],"agentforce_agents":["*","0Xxg70000020uCOCAY"]}`:   "agentforce_agents",
		`{"mode":"read_write","objects":["*"],"agentforce_messages":"always"}`:                   "agentforce_messages",
		`{"mode":"read_write","objects":["*"],"agentforce_agents":["0Xxg70000020uCOCAY"],"x":1}`: "x",
	}
	for p, want := range bad {
		if _, err := Validate("salesforce", json.RawMessage(p)); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: %v", p, err)
		}
	}
	// Salesforce only.
	if _, err := Validate("servicenow", json.RawMessage(`{"mode":"read_write","objects":["*"],"agentforce_agents":["*"]}`)); err == nil {
		t.Fatal("agentforce_agents accepted for servicenow")
	}
	// Ids keep their case (Salesforce ids are case-sensitive).
	out, err := Validate("salesforce", json.RawMessage(`{"mode":"read_write","objects":["*"],"agentforce_agents":["0Xxg70000020uCOCAY"]}`))
	if err != nil || !strings.Contains(string(out), "0Xxg70000020uCOCAY") {
		t.Fatalf("%s %v", out, err)
	}
}

func TestSaaSProfileAgentforceWidens(t *testing.T) {
	base := `{"mode":"read_write","objects":["*"],"agentforce_agents":["0Xxg70000020uCOCAY"]}`
	cases := []struct {
		next string
		want bool
	}{
		{base, false},
		{`{"mode":"read_write","objects":["*"]}`, false}, // absent = none: narrower
		{`{"mode":"read_write","objects":["*"],"agentforce_agents":["0Xxg70000020uCOCAY","0Xxg7000000OTHER1A"]}`, true},
		{`{"mode":"read_write","objects":["*"],"agentforce_agents":["*"]}`, true},
		{`{"mode":"read_write","objects":["*"],"agentforce_agents":["0Xxg70000020uCOCAY"],"agentforce_messages":"allow"}`, true},
		{`{"mode":"read_write","objects":["*"],"agentforce_agents":["0Xxg70000020uCOCAY"],"agentforce_messages":"approval"}`, false},
	}
	for _, c := range cases {
		got, err := Widens("salesforce", json.RawMessage(base), json.RawMessage(c.next))
		if err != nil || got != c.want {
			t.Fatalf("%s: widens=%v err=%v, want %v", c.next, got, err, c.want)
		}
	}
	// From no Agentforce agents to some widens.
	if got, _ := Widens("salesforce", json.RawMessage(`{"mode":"read_write","objects":["*"]}`), json.RawMessage(base)); !got {
		t.Fatal("granting an agent did not widen")
	}
}
