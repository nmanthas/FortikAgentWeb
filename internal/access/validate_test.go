package access_test

import (
	"encoding/json"
	"errors"
	"testing"

	"fortik/internal/access"
)

func TestValidateAcceptsDesignShapes(t *testing.T) {
	cases := []struct {
		system, in, want string
	}{
		{"gmail", `{"send":"internal_only","read":true,"max_recipients":25}`, `{"send":"internal_only","read":true,"max_recipients":25}`},
		{"gmail", ` { "max_recipients":0, "read":false, "send":"none" } `, `{"send":"none","read":false,"max_recipients":0}`},
		{"drive", `{"mode":"read_only","share":"none"}`, `{"mode":"read_only","share":"none"}`},
		{"github", `{"repos":["Acme/Web","acme/api"],"permissions":{"contents":"write","metadata":"read"},"allow_direct_token":true}`,
			`{"repos":["acme/api","acme/web"],"permissions":{"contents":"write","metadata":"read"},"allow_direct_token":true}`},
		{"github", `{"repos":[],"permissions":{}}`, `{"repos":[],"permissions":{},"allow_direct_token":false}`},
		{"aws", `{"mode":"read_write","services":["s3","ec2"],"denied_actions":["IAM:*","s3:Delete*"]}`,
			`{"mode":"read_write","services":["ec2","s3"],"denied_actions":["iam:*","s3:delete*"]}`},
		{"aws", `{"mode":"none","services":[]}`, `{"mode":"none","services":[],"denied_actions":[]}`},
		{"postgres", `{"upstreams":{"acme_prod":"read_only","acme_staging":"read_write"}}`, `{"upstreams":{"acme_prod":"read_only","acme_staging":"read_write"}}`},
	}
	for _, c := range cases {
		got, err := access.Validate(c.system, json.RawMessage(c.in))
		if err != nil {
			t.Errorf("%s %s: %v", c.system, c.in, err)
			continue
		}
		if string(got) != c.want {
			t.Errorf("%s: got %s want %s", c.system, got, c.want)
		}
	}
}

func TestValidateRejects(t *testing.T) {
	cases := []struct{ system, in string }{
		{"gmail", `{"send":"all","read":true,"max_recipients":1}`},
		{"gmail", `{"read":true,"max_recipients":1}`},
		{"gmail", `{"send":"any","max_recipients":1}`},
		{"gmail", `{"send":"any","read":true}`},
		{"gmail", `{"send":"any","read":"yes","max_recipients":1}`},
		{"gmail", `{"send":"any","read":true,"max_recipients":-1}`},
		{"gmail", `{"send":"any","read":true,"max_recipients":1000000}`},
		{"gmail", `{"send":"any","read":true,"max_recipients":1.5}`},
		{"gmail", `{"send":"any","read":true,"max_recipients":1,"bcc":true}`},
		{"drive", `{"mode":"read_write"}`},
		{"drive", `{"mode":"owner","share":"none"}`},
		{"drive", `{"mode":"read_only","share":"public"}`},
		{"github", `{"permissions":{}}`},
		{"github", `{"repos":[]}`},
		{"github", `{"repos":["not-a-repo"],"permissions":{}}`},
		{"github", `{"repos":["acme/api","ACME/api"],"permissions":{}}`},
		{"github", `{"repos":[],"permissions":{"administration":"write"}}`},
		{"github", `{"repos":[],"permissions":{"metadata":"write"}}`},
		{"github", `{"repos":[],"permissions":{"contents":"admin"}}`},
		{"github", `{"repos":[],"permissions":{},"allow_direct_token":"true"}`},
		{"aws", `{"mode":"read_write"}`},
		{"aws", `{"mode":"admin","services":[]}`},
		{"aws", `{"mode":"read_only","services":["S3 "]}`},
		{"aws", `{"mode":"read_only","services":["s3"],"denied_actions":["delete everything"]}`},
		{"aws", `{"mode":"read_only","services":["s3"],"denied_actions":["s3"]}`},
		{"postgres", `{}`},
		{"postgres", `{"upstreams":{"acme":"rw"}}`},
		{"postgres", `{"upstreams":{"bad name":"read_only"}}`},
		{"postgres", `{"upstreams":{"acme":"read_only"}} {}`},
		{"postgres", `null`},
		{"postgres", `[]`},
		{"postgres", ``},
		{"memory", `{}`},
	}
	for _, c := range cases {
		if _, err := access.Validate(c.system, json.RawMessage(c.in)); !errors.Is(err, access.ErrInvalidProfile) {
			t.Errorf("%s %s: want ErrInvalidProfile, got %v", c.system, c.in, err)
		}
	}
}

func TestWidens(t *testing.T) {
	cases := []struct {
		name, system, prev, next string
		want                     bool
	}{
		{"gmail same", "gmail", `{"send":"internal_only","read":true,"max_recipients":10}`, `{"send":"internal_only","read":true,"max_recipients":10}`, false},
		{"gmail send up", "gmail", `{"send":"internal_only","read":true,"max_recipients":10}`, `{"send":"any","read":true,"max_recipients":10}`, true},
		{"gmail send down", "gmail", `{"send":"any","read":true,"max_recipients":10}`, `{"send":"none","read":true,"max_recipients":10}`, false},
		{"gmail read on", "gmail", `{"send":"none","read":false,"max_recipients":0}`, `{"send":"none","read":true,"max_recipients":0}`, true},
		{"gmail more recipients", "gmail", `{"send":"any","read":true,"max_recipients":10}`, `{"send":"any","read":true,"max_recipients":11}`, true},
		{"gmail fewer recipients", "gmail", `{"send":"any","read":true,"max_recipients":10}`, `{"send":"any","read":true,"max_recipients":5}`, false},
		{"gmail from nothing", "gmail", ``, `{"send":"none","read":false,"max_recipients":0}`, false},
		{"gmail from nothing grants", "gmail", `null`, `{"send":"none","read":true,"max_recipients":0}`, true},
		{"drive mode up", "drive", `{"mode":"read_only","share":"none"}`, `{"mode":"read_write","share":"none"}`, true},
		{"drive share up", "drive", `{"mode":"read_write","share":"none"}`, `{"mode":"read_write","share":"internal_only"}`, true},
		{"drive narrower", "drive", `{"mode":"read_write","share":"any"}`, `{"mode":"read_only","share":"internal_only"}`, false},
		{"github new repo", "github", `{"repos":["acme/api"],"permissions":{}}`, `{"repos":["acme/api","acme/web"],"permissions":{}}`, true},
		{"github repo case", "github", `{"repos":["acme/api"],"permissions":{}}`, `{"repos":["ACME/API"],"permissions":{}}`, false},
		{"github drop repo", "github", `{"repos":["acme/api","acme/web"],"permissions":{"contents":"write"}}`, `{"repos":["acme/api"],"permissions":{"contents":"read"}}`, false},
		{"github perm up", "github", `{"repos":[],"permissions":{"contents":"read"}}`, `{"repos":[],"permissions":{"contents":"write"}}`, true},
		{"github new perm", "github", `{"repos":[],"permissions":{}}`, `{"repos":[],"permissions":{"issues":"read"}}`, true},
		{"github direct token", "github", `{"repos":[],"permissions":{}}`, `{"repos":[],"permissions":{},"allow_direct_token":true}`, true},
		{"aws mode up", "aws", `{"mode":"read_only","services":["s3"]}`, `{"mode":"read_write","services":["s3"]}`, true},
		{"aws new service", "aws", `{"mode":"read_only","services":["s3"]}`, `{"mode":"read_only","services":["s3","ec2"]}`, true},
		{"aws drop denial", "aws", `{"mode":"read_only","services":["s3"],"denied_actions":["s3:delete*"]}`, `{"mode":"read_only","services":["s3"]}`, true},
		{"aws add denial", "aws", `{"mode":"read_only","services":["s3"]}`, `{"mode":"read_only","services":["s3"],"denied_actions":["s3:delete*"]}`, false},
		{"aws from nothing with denials", "aws", ``, `{"mode":"none","services":[],"denied_actions":["*"]}`, false},
		{"pg new upstream", "postgres", `{"upstreams":{"a":"read_only"}}`, `{"upstreams":{"a":"read_only","b":"read_only"}}`, true},
		{"pg none upstream added", "postgres", `{"upstreams":{"a":"read_only"}}`, `{"upstreams":{"a":"read_only","b":"none"}}`, false},
		{"pg mode up", "postgres", `{"upstreams":{"a":"read_only"}}`, `{"upstreams":{"a":"read_write"}}`, true},
		{"pg remove upstream", "postgres", `{"upstreams":{"a":"read_write","b":"read_only"}}`, `{"upstreams":{"a":"read_only"}}`, false},
	}
	for _, c := range cases {
		got, err := access.Widens(c.system, json.RawMessage(c.prev), json.RawMessage(c.next))
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s: widens=%v want %v", c.name, got, c.want)
		}
	}
}

func TestWidensFailsClosedOnInvalidInput(t *testing.T) {
	if w, err := access.Widens("drive", nil, json.RawMessage(`{"mode":"x","share":"none"}`)); err == nil || !w {
		t.Fatalf("invalid next: widens=%v err=%v", w, err)
	}
	if w, err := access.Widens("drive", json.RawMessage(`{"bogus":1}`), json.RawMessage(`{"mode":"none","share":"none"}`)); err == nil || !w {
		t.Fatalf("invalid prev: widens=%v err=%v", w, err)
	}
	if w, err := access.Widens("shell", nil, json.RawMessage(`{}`)); err == nil || !w {
		t.Fatalf("unknown system: widens=%v err=%v", w, err)
	}
}
