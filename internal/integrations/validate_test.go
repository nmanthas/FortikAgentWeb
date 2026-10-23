package integrations

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestSchemasMatchDesign(t *testing.T) {
	want := map[string][]string{
		SystemGoogle:       {"primary_domain*", "internal_domains", "test_user*", "admin_user", "service_account_json*!"},
		SystemGitHub:       {"api_base_url", "app_id*", "installation_id*", "private_key_pem*!"},
		SystemAWS:          {"region*", "role_arn*", "sts_endpoint", "iam_endpoint", "access_key_id*!", "secret_access_key*!", "external_id!"},
		SystemPostgres:     {"host*", "port", "database*", "sslmode", "environment*", "admin_user*", "read_role*", "write_role*", "admin_password*!"},
		SystemTemporal:     {"host_port*", "namespace", "tls", "api_key!"},
		SystemCelery:       {"queues", "redis_url*!"},
		SystemQueueWebhook: {"url*", "secret*!"},
		SystemMemory:       {"host*", "port", "database*", "sslmode", "dimension", "admin_user*", "admin_password*!"},
	}
	got := Schemas()
	if len(got) != len(want) {
		t.Fatalf("%d schemas", len(got))
	}
	for _, s := range got {
		var keys []string
		for _, f := range s.Fields {
			k := f.Key
			if f.Required {
				k += "*"
			}
			if f.Secret {
				k += "!"
				if f.Type != FieldPassword && f.Type != FieldTextarea {
					t.Errorf("%s.%s: secret fields must render as password/textarea", s.System, f.Key)
				}
			}
			if f.Label == "" || f.Help == "" {
				t.Errorf("%s.%s: label and help are required", s.System, f.Key)
			}
			if f.Type == FieldSelect && len(f.Options) == 0 {
				t.Errorf("%s.%s: select without options", s.System, f.Key)
			}
			keys = append(keys, k)
		}
		if strings.Join(keys, ",") != strings.Join(want[s.System], ",") {
			t.Errorf("%s fields = %v, want %v", s.System, keys, want[s.System])
		}
		if s.Multi != (s.System == SystemPostgres || s.System == SystemMemory) {
			t.Errorf("%s: multi = %v", s.System, s.Multi)
		}
	}
	// Copies: mutating the result must not change the package's schema.
	got[0].Fields[0].Key = "mutated"
	if Schemas()[0].Fields[0].Key == "mutated" {
		t.Fatal("Schemas returned shared state")
	}
	gh, _ := SchemaFor(SystemGitHub)
	if f, _ := fieldByKey(gh, "installation_id"); !strings.Contains(f.Help, "/settings/installations/") {
		t.Error("installation_id help must say where to find it")
	}
}

func TestParseKeyAndSecretName(t *testing.T) {
	for key, sys := range map[string]string{"github": "github", "aws": "aws", "google_workspace": "google_workspace", "postgres:acme_prod": "postgres", "postgres:a": "postgres"} {
		got, err := ParseKey(key)
		if err != nil || got != sys {
			t.Errorf("ParseKey(%q) = %q, %v", key, got, err)
		}
	}
	for _, key := range []string{"", "postgres", "postgres:", "postgres:Acme", "postgres:1abc", "postgres:a-b", "postgres:" + strings.Repeat("a", 64), "gmail", "GitHub", "github ", "postgres:a/b", "postgres:../x"} {
		if _, err := ParseKey(key); !errors.Is(err, ErrInvalid) {
			t.Errorf("ParseKey(%q) accepted", key)
		}
	}
	if n := SecretName("postgres:acme_prod", "admin_password"); n != "integration/postgres/acme_prod/admin_password" {
		t.Error(n)
	}
	if n := SecretName("github", "private_key_pem"); n != "integration/github/private_key_pem" {
		t.Error(n)
	}
}

func validConfigs() map[string]map[string]any {
	return map[string]map[string]any{
		SystemGoogle:   {"primary_domain": "Example.com", "internal_domains": []string{"example.co.uk", "EXAMPLE.co.uk", ""}, "test_user": "agent-test@example.com"},
		SystemGitHub:   {"app_id": 12345, "installation_id": "67890"},
		SystemAWS:      {"region": "us-east-1", "role_arn": "arn:aws:iam::123456789012:role/fortik-agents", "sts_endpoint": "http://127.0.0.1:5000/"},
		SystemPostgres: {"host": "db.internal", "database": "acme", "environment": "prod", "admin_user": "fortik_admin", "read_role": "acme_read", "write_role": "acme_write"},
	}
}

func TestNormalizeConfig(t *testing.T) {
	for sys, cfg := range validConfigs() {
		s, _ := SchemaFor(sys)
		out, err := normalizeConfig(s, raw(cfg))
		if err != nil {
			t.Fatalf("%s: %v", sys, err)
		}
		b, _ := json.Marshal(out)
		t.Logf("%s: %s", sys, b)
	}
	g, _ := SchemaFor(SystemGoogle)
	out, _ := normalizeConfig(g, raw(validConfigs()[SystemGoogle]))
	if out["primary_domain"] != "example.com" || len(out["internal_domains"].([]string)) != 1 {
		t.Errorf("google normalisation: %v", out)
	}
	gh, _ := SchemaFor(SystemGitHub)
	out, _ = normalizeConfig(gh, raw(validConfigs()[SystemGitHub]))
	if out["app_id"] != "12345" || out["installation_id"] != "67890" || out["api_base_url"] != "https://api.github.com" {
		t.Errorf("github defaults/normalisation: %v", out)
	}
	a, _ := SchemaFor(SystemAWS)
	out, _ = normalizeConfig(a, raw(validConfigs()[SystemAWS]))
	if out["sts_endpoint"] != "http://127.0.0.1:5000" {
		t.Errorf("aws endpoint: %v", out)
	}
	if _, ok := out["iam_endpoint"]; ok {
		t.Error("omitted optional field without default must stay absent")
	}
	p, _ := SchemaFor(SystemPostgres)
	out, _ = normalizeConfig(p, raw(validConfigs()[SystemPostgres]))
	if out["port"] != int64(5432) || out["sslmode"] != "require" {
		t.Errorf("postgres defaults: %v", out)
	}
}

func TestNormalizeConfigRejects(t *testing.T) {
	cases := []struct {
		sys    string
		modify map[string]any
		drop   string
		want   string
	}{
		{SystemGoogle, nil, "primary_domain", "required"},
		{SystemGoogle, map[string]any{"primary_domain": "not a domain"}, "", "domain"},
		{SystemGoogle, map[string]any{"test_user": "someone@other.com"}, "", "primary domain"},
		{SystemGoogle, map[string]any{"test_user": "no-at-sign"}, "", "email"},
		{SystemGoogle, map[string]any{"internal_domains": "example.org"}, "", "list"},
		{SystemGoogle, map[string]any{"service_account_json": "{}"}, "", "secret field"},
		{SystemGoogle, map[string]any{"bogus": 1}, "", "unknown config field"},
		{SystemGitHub, map[string]any{"app_id": "abc"}, "", "positive number"},
		{SystemGitHub, map[string]any{"app_id": 1.5}, "", "positive number"},
		{SystemGitHub, map[string]any{"app_id": true}, "", "string or an integer"},
		{SystemGitHub, map[string]any{"api_base_url": "http://github.example.com"}, "", "https"},
		{SystemGitHub, map[string]any{"api_base_url": "https://user:pw@github.example.com"}, "", "credentials"},
		{SystemGitHub, map[string]any{"api_base_url": "ftp://x"}, "", "https"},
		{SystemGitHub, map[string]any{"installation_id": ""}, "", "required"},
		{SystemAWS, map[string]any{"region": "mars-1"}, "", "region"},
		{SystemAWS, map[string]any{"role_arn": "arn:aws:iam::123:role/x"}, "", "ARN"},
		{SystemAWS, map[string]any{"role_arn": "arn:aws:iam::123456789012:user/x"}, "", "ARN"},
		{SystemPostgres, map[string]any{"port": 70000}, "", "65535"},
		{SystemPostgres, map[string]any{"port": "abc"}, "", "integer"},
		{SystemPostgres, map[string]any{"environment": "qa"}, "", "prod, staging, dev"},
		{SystemPostgres, map[string]any{"sslmode": "maybe"}, "", "one of"},
		{SystemPostgres, map[string]any{"read_role": "x; DROP ROLE y"}, "", "role name"},
		{SystemPostgres, map[string]any{"admin_user": "acme_read"}, "", "separate role"},
		{SystemPostgres, map[string]any{"write_role": "acme_read"}, "", "different roles"},
		{SystemPostgres, map[string]any{"read_role": "fortik_a_bot"}, "", "reserved"},
		{SystemGitHub, map[string]any{"app_id": "12345678901234567890"}, "", "positive number"},
		{SystemPostgres, map[string]any{"host": "bad host/x"}, "", "hostname"},
		{SystemPostgres, map[string]any{"database": strings.Repeat("d", 64)}, "", "database name"},
		{SystemPostgres, nil, "environment", "required"},
	}
	for _, c := range cases {
		cfg := validConfigs()[c.sys]
		for k, v := range c.modify {
			cfg[k] = v
		}
		if c.drop != "" {
			delete(cfg, c.drop)
		}
		s, _ := SchemaFor(c.sys)
		_, err := normalizeConfig(s, raw(cfg))
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s %v drop=%q: got %v, want error containing %q", c.sys, c.modify, c.drop, err, c.want)
		}
	}
}

func TestValidateSecrets(t *testing.T) {
	pemKey := testPEM(t)
	sa := testSAJSON(t)
	gh, _ := SchemaFor(SystemGitHub)
	set, remove, err := validateSecrets(gh, map[string]*string{"private_key_pem": strp("\n" + pemKey + "\n\n")})
	if err != nil || set["private_key_pem"] != strings.TrimSpace(pemKey)+"\n" || len(remove) != 0 {
		t.Fatalf("pem: %v", err)
	}
	g, _ := SchemaFor(SystemGoogle)
	if _, _, err := validateSecrets(g, map[string]*string{"service_account_json": strp(sa)}); err != nil {
		t.Fatalf("service account: %v", err)
	}
	a, _ := SchemaFor(SystemAWS)
	set, remove, err = validateSecrets(a, map[string]*string{"access_key_id": strp(" AKIAIOSFODNN7EXAMPLE "), "secret_access_key": strp("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"), "external_id": nil})
	if err != nil || set["access_key_id"] != "AKIAIOSFODNN7EXAMPLE" || len(remove) != 1 || remove[0] != "external_id" {
		t.Fatalf("aws: %v %v %v", set, remove, err)
	}

	saMap := func(mod func(m map[string]any)) string {
		var m map[string]any
		_ = json.Unmarshal([]byte(sa), &m)
		mod(m)
		b, _ := json.Marshal(m)
		return string(b)
	}
	const sentinel = "SENTINEL-SECRET-VALUE"
	bad := []struct {
		sys    string
		in     map[string]*string
		want   string
		secret string
	}{
		{SystemGitHub, map[string]*string{"private_key_pem": strp("")}, "must not be empty", ""},
		{SystemGitHub, map[string]*string{"private_key_pem": nil}, "cannot be removed", ""},
		{SystemGitHub, map[string]*string{"private_key_pem": strp(sentinel)}, "PEM", sentinel},
		{SystemGitHub, map[string]*string{"private_key_pem": strp("-----BEGIN RSA PRIVATE KEY-----\n" + sentinel + "\n-----END RSA PRIVATE KEY-----\n")}, "PEM", sentinel},
		{SystemGitHub, map[string]*string{"private_key_pem": strp(strings.Replace(pemKey, "MII", "MIX", 1))}, "", ""},
		{SystemGitHub, map[string]*string{"private_key_pem": strp(pemKey + pemKey)}, "exactly one", ""},
		{SystemGitHub, map[string]*string{"app_id": strp("1")}, "not a secret field", ""},
		{SystemGitHub, map[string]*string{"nope": strp("1")}, "unknown secret field", ""},
		{SystemGoogle, map[string]*string{"service_account_json": strp(sentinel)}, "JSON object", sentinel},
		{SystemGoogle, map[string]*string{"service_account_json": strp(saMap(func(m map[string]any) { m["type"] = "authorized_user" }))}, "service_account", ""},
		{SystemGoogle, map[string]*string{"service_account_json": strp(saMap(func(m map[string]any) { delete(m, "client_email") }))}, "client_email", ""},
		{SystemGoogle, map[string]*string{"service_account_json": strp(saMap(func(m map[string]any) { m["private_key"] = sentinel }))}, "private_key", sentinel},
		{SystemGoogle, map[string]*string{"service_account_json": strp(saMap(func(m map[string]any) { m["token_uri"] = "http://evil.example/token" }))}, "token_uri", ""},
		{SystemAWS, map[string]*string{"access_key_id": strp("lower-case-key-123")}, "access key", ""},
		{SystemAWS, map[string]*string{"secret_access_key": strp("short")}, "secret access key", ""},
		{SystemAWS, map[string]*string{"external_id": strp("x")}, "2-1224", ""},
		{SystemPostgres, map[string]*string{"admin_password": strp("a\x00b")}, "NUL", ""},
	}
	for i, c := range bad {
		s, _ := SchemaFor(c.sys)
		_, _, err := validateSecrets(s, c.in)
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("case %d (%s): got %v, want error containing %q", i, c.sys, err, c.want)
			continue
		}
		if c.secret != "" && strings.Contains(err.Error(), c.secret) {
			t.Errorf("case %d: error echoes the secret value: %v", i, err)
		}
	}
}

func TestSanitize(t *testing.T) {
	sa := testSAJSON(t)
	var m map[string]string
	_ = json.Unmarshal([]byte(sa), &m)
	pemKey := testPEM(t)
	lines := strings.Split(pemKey, "\n")
	vals := map[string]string{"service_account_json": sa, "private_key_pem": pemKey, "admin_password": "hunter2-pw"}
	msg := "dial failed: password hunter2-pw rejected; key " + m["private_key"] + " id=" + m["private_key_id"] +
		" line " + lines[3] + " escaped " + strings.ReplaceAll(pemKey, "\n", `\n`) + "\x1b[31m\nend"
	out := Sanitize(msg, vals)
	for _, leak := range []string{"hunter2-pw", m["private_key_id"], lines[3], lines[5], "\x1b", "\n"} {
		if strings.Contains(out, leak) {
			t.Errorf("sanitised message still contains %q: %s", leak, out)
		}
	}
	if !strings.HasPrefix(out, "dial failed: password *** rejected") {
		t.Errorf("unexpected: %s", out)
	}
	long := Sanitize(strings.Repeat("x", 5000), nil)
	if len(long) > MaxErrorLen+3 {
		t.Errorf("not capped: %d", len(long))
	}
	if f := Fingerprint("abc"); f != "ba7816bf" {
		t.Errorf("fingerprint = %s", f)
	}
}

func TestResolvedHelpers(t *testing.T) {
	r := Resolved{Integration: Integration{Key: "postgres:acme", Status: "ok", SecretFields: []string{"admin_password"}},
		ConfigMap: map[string]any{"host": "h", "port": float64(5433), "list": []any{"a", "b"}, "b": true},
		Secrets:   map[string]string{"admin_password": "TOPSECRET"}}
	if r.Text("host") != "h" || r.Int("port") != 5433 || len(r.Strings("list")) != 2 || !r.Bool("b") || r.Name() != "acme" || r.Secret("admin_password") != "TOPSECRET" {
		t.Fatal("accessors")
	}
	b, _ := json.Marshal(r)
	for _, s := range []string{r.String(), r.GoString(), string(b), fmt.Sprintf("%v %+v %#v %s", r, r, r, r)} {
		if strings.Contains(s, "TOPSECRET") {
			t.Fatalf("Resolved formatting leaks a secret: %s", s)
		}
	}
}

func TestMemoryKeysAndValidation(t *testing.T) {
	for key, want := range map[string]string{"memory:support": SystemMemory, "memory:a_1": SystemMemory} {
		if got, err := ParseKey(key); err != nil || got != want {
			t.Errorf("ParseKey(%q) = %q, %v", key, got, err)
		}
	}
	for _, key := range []string{"memory", "memory:", "memory:Bad", "memory:1x", "memory:a-b"} {
		if _, err := ParseKey(key); err == nil {
			t.Errorf("ParseKey(%q) accepted", key)
		}
	}
	if n := (Resolved{Key: "memory:support"}).Name(); n != "support" {
		t.Errorf("Name = %q", n)
	}
	for _, d := range []int64{0, -1, 16001} {
		if err := configValidators["memory.dimension"](d); err == nil {
			t.Errorf("dimension %d accepted", d)
		}
	}
	if err := configValidators["memory.dimension"](int64(1536)); err != nil {
		t.Errorf("dimension 1536: %v", err)
	}
}
