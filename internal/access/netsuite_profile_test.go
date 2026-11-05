package access

import (
	"encoding/json"
	"testing"
)

func TestNetSuiteProfile(t *testing.T) {
	for _, bad := range []string{
		`{"mode":"read_write","record_types":["*"]}`,                          // suiteql missing
		`{"mode":"read_write","suiteql":true}`,                                // record_types missing
		`{"mode":"admin","record_types":["*"],"suiteql":true}`,                // bad mode
		`{"mode":"read_only","record_types":["*","customer"],"suiteql":true}`, // * mixed
		`{"mode":"read_only","record_types":["bad type"],"suiteql":true}`,
		`{"mode":"read_only","record_types":["customer"],"suiteql":true,"extra":1}`,
	} {
		if _, err := Parse("netsuite", json.RawMessage(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	p, err := Parse("netsuite", json.RawMessage(`{"mode":"read_only","record_types":["Customer","salesOrder"],"suiteql":false}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := p.(NetSuiteProfile).RecordTypes; len(got) != 2 || got[0] != "customer" || got[1] != "salesorder" {
		t.Fatalf("normalised record types: %v", got)
	}
	narrow := json.RawMessage(`{"mode":"read_only","record_types":["customer"],"suiteql":false}`)
	for next, want := range map[string]bool{
		`{"mode":"read_only","record_types":["customer"],"suiteql":false}`:          false,
		`{"mode":"read_write","record_types":["customer"],"suiteql":false}`:         true,
		`{"mode":"read_only","record_types":["customer"],"suiteql":true}`:           true,
		`{"mode":"read_only","record_types":["customer","vendor"],"suiteql":false}`: true,
		`{"mode":"read_only","record_types":["*"],"suiteql":false}`:                 true,
		`{"mode":"none","record_types":["customer"],"suiteql":false}`:               false,
	} {
		got, err := Widens("netsuite", narrow, json.RawMessage(next))
		if err != nil || got != want {
			t.Errorf("widens %s: %v %v (want %v)", next, got, err, want)
		}
	}
	if w, _ := Widens("netsuite", json.RawMessage(`{"mode":"read_write","record_types":["*"],"suiteql":true}`),
		json.RawMessage(`{"mode":"read_only","record_types":["vendor"],"suiteql":false}`)); w {
		t.Error("narrowing from * reported as widening")
	}
}

func TestNetSuiteQuickStartTools(t *testing.T) {
	for _, bad := range []string{
		`{"mode":"read_only","record_types":["*"],"suiteql":false,"quickstart_tools":["*","read_record"]}`,
		`{"mode":"read_only","record_types":["*"],"suiteql":false,"quickstart_tools":["Bad Tool"]}`,
		`{"mode":"read_only","record_types":["*"],"suiteql":false,"quickstart_tools":["read_record","read_record"]}`,
	} {
		if _, err := Parse("netsuite", json.RawMessage(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	p, err := Parse("netsuite", json.RawMessage(`{"mode":"read_write","record_types":["*"],"suiteql":false,"quickstart_tools":["read_record","list_records"]}`))
	if err != nil {
		t.Fatal(err)
	}
	np := p.(NetSuiteProfile)
	if !np.AllowsQuickStartTool("read_record") || np.AllowsQuickStartTool("update_record") {
		t.Fatalf("allowlist %v", np.QuickStartTools)
	}
	all, _ := Parse("netsuite", json.RawMessage(`{"mode":"read_write","record_types":["*"],"suiteql":false}`))
	if !all.(NetSuiteProfile).AllowsQuickStartTool("update_record") {
		t.Fatal("an absent list must allow every tool (the mode still applies)")
	}
	narrow := json.RawMessage(`{"mode":"read_write","record_types":["*"],"suiteql":false,"quickstart_tools":["read_record"]}`)
	for next, want := range map[string]bool{
		`{"mode":"read_write","record_types":["*"],"suiteql":false,"quickstart_tools":["read_record"]}`:                 false,
		`{"mode":"read_write","record_types":["*"],"suiteql":false,"quickstart_tools":[]}`:                              false,
		`{"mode":"read_write","record_types":["*"],"suiteql":false,"quickstart_tools":["read_record","update_record"]}`: true,
		`{"mode":"read_write","record_types":["*"],"suiteql":false,"quickstart_tools":["*"]}`:                           true,
		`{"mode":"read_write","record_types":["*"],"suiteql":false}`:                                                    true,
	} {
		got, err := Widens("netsuite", narrow, json.RawMessage(next))
		if err != nil || got != want {
			t.Errorf("widens %s: %v %v (want %v)", next, got, err, want)
		}
	}
}
