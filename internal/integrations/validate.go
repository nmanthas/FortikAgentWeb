package integrations

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// Limits on submitted values.
const (
	maxTextLen   = 2048
	maxSecretLen = 64 << 10
	maxListLen   = 100
)

var (
	domainRe   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
	emailLocal = regexp.MustCompile(`^[A-Za-z0-9._%+'-]{1,64}$`)
	hostRe     = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
	roleRe     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,62}$`)
	dbNameRe   = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_$-]{0,62}$`)
	numericID  = regexp.MustCompile(`^[1-9][0-9]{0,18}$`) // fits int64
	regionRe   = regexp.MustCompile(`^[a-z]{2}(?:-[a-z]+)+-[0-9]{1,2}$`)
	roleARNRe  = regexp.MustCompile(`^arn:aws(?:-[a-z]+)*:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}$`)
	accessKey  = regexp.MustCompile(`^[A-Z0-9]{16,128}$`)
	externalID = regexp.MustCompile(`^[A-Za-z0-9+=,.@:/_-]+$`) // length 2..1224 checked separately
	// Temporal namespace names; Celery (kombu) queue names. Queue names
	// exclude kombu's priority separator and anything that is not printable.
	temporalNSRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$`)
	celeryQueue  = regexp.MustCompile(`^[A-Za-z0-9_.:@-]{1,200}$`)
)

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// numericTextFields accept a JSON integer as well as a string of digits and
// are normalised to a string (IDs never pass through float64).
var numericTextFields = map[string]bool{"github.app_id": true, "github.installation_id": true}

// configNormalizers canonicalise values before validation.
var configNormalizers = map[string]func(any) any{
	"google_workspace.primary_domain":   lowerAny,
	"google_workspace.internal_domains": lowerAny,
	"google_workspace.test_user":        lowerAny,
	"google_workspace.admin_user":       lowerAny,
	"github.api_base_url":               trimSlash,
	"aws.sts_endpoint":                  trimSlash,
	"aws.iam_endpoint":                  trimSlash,
}

func lowerAny(v any) any {
	switch t := v.(type) {
	case string:
		return strings.ToLower(t)
	case []string:
		out := make([]string, 0, len(t))
		for _, s := range t {
			if s = strings.ToLower(s); !slices.Contains(out, s) {
				out = append(out, s)
			}
		}
		return out
	}
	return v
}

func trimSlash(v any) any {
	if s, ok := v.(string); ok {
		return strings.TrimRight(s, "/")
	}
	return v
}

// configValidators check one normalised non-secret value (strings already
// trimmed; lists are []string). Messages never echo the value.
var configValidators = map[string]func(any) error{
	"google_workspace.primary_domain":   func(v any) error { return checkDomain(v.(string)) },
	"google_workspace.internal_domains": func(v any) error { return eachString(v, checkDomain) },
	"google_workspace.test_user":        func(v any) error { return checkEmail(v.(string)) },
	"google_workspace.admin_user":       func(v any) error { return checkEmail(v.(string)) },
	"github.api_base_url":               func(v any) error { return checkURL(v.(string)) },
	"github.app_id":                     func(v any) error { return match(numericID, v, "a positive number") },
	"github.installation_id":            func(v any) error { return match(numericID, v, "a positive number") },
	"aws.region":                        func(v any) error { return match(regionRe, v, "an AWS region such as us-east-1") },
	"aws.role_arn": func(v any) error {
		return match(roleARNRe, v, "an IAM role ARN (arn:aws:iam::<12-digit account>:role/<name>)")
	},
	"aws.sts_endpoint":    func(v any) error { return checkURL(v.(string)) },
	"aws.iam_endpoint":    func(v any) error { return checkURL(v.(string)) },
	"postgres.host":       func(v any) error { return checkHost(v.(string)) },
	"postgres.port":       func(v any) error { return checkPort(v.(int64)) },
	"postgres.database":   func(v any) error { return match(dbNameRe, v, "a database name (letters, digits, _ $ -; at most 63)") },
	"postgres.admin_user": func(v any) error { return match(roleRe, v, "a role name (letters, digits, _; at most 63)") },
	"postgres.read_role":  func(v any) error { return match(roleRe, v, "a role name (letters, digits, _; at most 63)") },
	"postgres.write_role": func(v any) error { return match(roleRe, v, "a role name (letters, digits, _; at most 63)") },
	"memory.host":         func(v any) error { return checkHost(v.(string)) },
	"memory.port":         func(v any) error { return checkPort(v.(int64)) },
	"memory.database":     func(v any) error { return match(dbNameRe, v, "a database name (letters, digits, _ $ -; at most 63)") },
	"memory.admin_user":   func(v any) error { return match(roleRe, v, "a role name (letters, digits, _; at most 63)") },
	"memory.dimension": func(v any) error {
		if d := v.(int64); d < 1 || d > 16000 {
			return errors.New("must be between 1 and 16000 (pgvector's limit)")
		}
		return nil
	},
	"temporal.host_port": func(v any) error { return checkHostPort(v.(string)) },
	"temporal.namespace": func(v any) error {
		return match(temporalNSRe, v, "a Temporal namespace (letters, digits, . _ -; at most 255)")
	},
	"celery.queues": func(v any) error {
		if len(v.([]string)) == 0 {
			return errors.New("list at least one queue (Celery's default queue is \"celery\")")
		}
		return eachString(v, func(s string) error {
			return match(celeryQueue, s, "queue names of letters, digits and _ . : @ - (at most 200)")
		})
	},
	"queue_webhook.url": func(v any) error { return checkURL(v.(string)) },
}

// secretValidators check (and may normalise, e.g. trim) one secret value.
// Messages never contain any part of the value.
var secretValidators = map[string]func(string) (string, error){
	"google_workspace.service_account_json": checkServiceAccountJSON,
	"github.private_key_pem":                checkRSAPrivateKeyPEM,
	"aws.access_key_id": func(s string) (string, error) {
		s = strings.TrimSpace(s)
		if !accessKey.MatchString(s) {
			return "", errors.New("must be an AWS access key ID (16-128 upper-case letters and digits)")
		}
		return s, nil
	},
	"aws.secret_access_key": func(s string) (string, error) {
		s = strings.TrimSpace(s)
		if len(s) < 16 || len(s) > 256 || strings.ContainsAny(s, " \t\r\n") {
			return "", errors.New("must be an AWS secret access key (16-256 characters, no spaces)")
		}
		return s, nil
	},
	"temporal.api_key": func(s string) (string, error) {
		s = strings.TrimSpace(s)
		if len(s) < 8 || len(s) > 8192 || strings.ContainsAny(s, " \t\r\n") {
			return "", errors.New("must be a Temporal API key (8-8192 characters, no spaces)")
		}
		return s, nil
	},
	"celery.redis_url": checkRedisURL,
	"queue_webhook.secret": func(s string) (string, error) {
		s = strings.TrimSpace(s)
		if len(s) < 16 || len(s) > 1024 || strings.IndexFunc(s, unicode.IsControl) >= 0 {
			return "", errors.New("must be 16-1024 characters without control characters (use a long random value)")
		}
		return s, nil
	},
	"aws.external_id": func(s string) (string, error) {
		s = strings.TrimSpace(s)
		if len(s) < 2 || len(s) > 1224 || !externalID.MatchString(s) {
			return "", errors.New("must be 2-1224 characters of letters, digits and +=,.@:/_-")
		}
		return s, nil
	},
}

// normalizeConfig validates the submitted non-secret config against the
// schema and returns it with defaults applied. Unknown keys, secret fields
// and wrongly typed values are rejected.
func normalizeConfig(s Schema, raw map[string]json.RawMessage) (map[string]any, error) {
	out := map[string]any{}
	for k := range raw {
		f, ok := fieldByKey(s, k)
		if !ok {
			return nil, invalid("unknown config field %q for %s", truncate(k, 64), s.System)
		}
		if f.Secret {
			return nil, invalid("%s is a secret field: send it under \"secrets\", not \"config\"", k)
		}
	}
	for _, f := range s.Fields {
		if f.Secret {
			continue
		}
		r, present := raw[f.Key]
		if present && !isNull(r) {
			v, err := decodeField(s.System, f, r)
			if err != nil {
				return nil, err
			}
			if v != nil {
				if norm := configNormalizers[s.System+"."+f.Key]; norm != nil {
					v = norm(v)
				}
				if check := configValidators[s.System+"."+f.Key]; check != nil {
					if err := check(v); err != nil {
						return nil, invalid("%s: %v", f.Key, err)
					}
				}
				out[f.Key] = v
				continue
			}
		}
		switch {
		case f.Default != nil:
			switch d := f.Default.(type) {
			case int:
				out[f.Key] = int64(d)
			case []string:
				out[f.Key] = append([]string(nil), d...)
			default:
				out[f.Key] = f.Default
			}
		case f.Required:
			return nil, invalid("%s (%s) is required", f.Key, f.Label)
		}
	}
	if err := crossValidate(s.System, out); err != nil {
		return nil, err
	}
	return out, nil
}

func isNull(r json.RawMessage) bool { return bytes.Equal(bytes.TrimSpace(r), []byte("null")) }

// decodeField decodes one value by field type. It returns (nil, nil) for an
// empty optional value (treated as omitted).
func decodeField(system string, f Field, r json.RawMessage) (any, error) {
	switch f.Type {
	case FieldText, FieldTextarea:
		var s string
		if err := json.Unmarshal(r, &s); err != nil {
			if !numericTextFields[system+"."+f.Key] {
				return nil, invalid("%s must be a string", f.Key)
			}
			var n json.Number
			if json.Unmarshal(r, &n) != nil {
				return nil, invalid("%s must be a string or an integer", f.Key)
			}
			s = n.String()
		}
		s = strings.TrimSpace(s)
		if len(s) > maxTextLen {
			return nil, invalid("%s is too long (max %d)", f.Key, maxTextLen)
		}
		if strings.ContainsRune(s, 0) {
			return nil, invalid("%s must not contain NUL", f.Key)
		}
		if s == "" {
			if f.Required {
				return nil, invalid("%s (%s) is required", f.Key, f.Label)
			}
			return nil, nil
		}
		return s, nil
	case FieldList:
		var l []string
		if err := json.Unmarshal(r, &l); err != nil {
			return nil, invalid("%s must be a list of strings", f.Key)
		}
		if len(l) > maxListLen {
			return nil, invalid("%s has too many entries (max %d)", f.Key, maxListLen)
		}
		out := make([]string, 0, len(l))
		for _, e := range l {
			e = strings.TrimSpace(e)
			if e == "" {
				continue
			}
			if len(e) > maxTextLen {
				return nil, invalid("%s: entry too long", f.Key)
			}
			if !slices.Contains(out, e) {
				out = append(out, e)
			}
		}
		if len(out) == 0 {
			if f.Required {
				return nil, invalid("%s (%s) is required", f.Key, f.Label)
			}
			return []string{}, nil
		}
		return out, nil
	case FieldSelect:
		var s string
		if err := json.Unmarshal(r, &s); err != nil {
			return nil, invalid("%s must be a string", f.Key)
		}
		s = strings.TrimSpace(s)
		if s == "" && !f.Required {
			return nil, nil
		}
		if !slices.Contains(f.Options, s) {
			return nil, invalid("%s must be one of %s", f.Key, strings.Join(f.Options, ", "))
		}
		return s, nil
	case FieldNumber:
		var n json.Number
		if err := json.Unmarshal(r, &n); err != nil {
			var s string
			if json.Unmarshal(r, &s) != nil {
				return nil, invalid("%s must be a number", f.Key)
			}
			n = json.Number(strings.TrimSpace(s))
		}
		if n == "" && !f.Required {
			return nil, nil
		}
		i, err := strconv.ParseInt(n.String(), 10, 64)
		if err != nil {
			return nil, invalid("%s must be an integer", f.Key)
		}
		return i, nil
	case FieldBool:
		var b bool
		if err := json.Unmarshal(r, &b); err != nil {
			return nil, invalid("%s must be true or false", f.Key)
		}
		return b, nil
	default:
		return nil, invalid("%s: unsupported field type", f.Key)
	}
}

func crossValidate(system string, cfg map[string]any) error {
	switch system {
	case SystemGoogle:
		primary, _ := cfg["primary_domain"].(string)
		internal, _ := cfg["internal_domains"].([]string)
		user, _ := cfg["test_user"].(string)
		at := strings.LastIndexByte(user, '@')
		domain := user[at+1:]
		if domain != primary && !slices.Contains(internal, domain) {
			return invalid("test_user must be an address in the primary domain or one of the internal domains")
		}
	case SystemPostgres:
		admin, _ := cfg["admin_user"].(string)
		read, _ := cfg["read_role"].(string)
		write, _ := cfg["write_role"].(string)
		if admin == read || admin == write {
			return invalid("admin_user must be a separate role from read_role and write_role")
		}
		if read == write {
			return invalid("read_role and write_role must be different roles")
		}
		// fortik_a_* are the broker's per-agent login roles (internal/broker/pgroles).
		for _, r := range []string{admin, read, write} {
			if strings.HasPrefix(strings.ToLower(r), "fortik_a_") {
				return invalid("roles named fortik_a_* are reserved for Fortik-managed agent roles")
			}
		}
	}
	return nil
}

// validateSecrets checks submitted secrets. A string sets the field (empty
// strings are rejected: omit the field to keep the stored value); null
// removes an optional field. Returns the values to store and the fields to
// remove.
func validateSecrets(s Schema, in map[string]*string) (map[string]string, []string, error) {
	set := map[string]string{}
	var remove []string
	for k, v := range in {
		f, ok := fieldByKey(s, k)
		if !ok {
			return nil, nil, invalid("unknown secret field %q for %s", truncate(k, 64), s.System)
		}
		if !f.Secret {
			return nil, nil, invalid("%s is not a secret field: send it under \"config\"", k)
		}
		if v == nil {
			if f.Required {
				return nil, nil, invalid("%s is required and cannot be removed (send a new value to replace it)", k)
			}
			remove = append(remove, k)
			continue
		}
		val := *v
		if val == "" {
			return nil, nil, invalid("%s must not be empty (omit it to keep the current value)", k)
		}
		if len(val) > maxSecretLen {
			return nil, nil, invalid("%s is too long", k)
		}
		if strings.ContainsRune(val, 0) {
			return nil, nil, invalid("%s must not contain NUL", k)
		}
		if check := secretValidators[s.System+"."+k]; check != nil {
			norm, err := check(val)
			if err != nil {
				return nil, nil, invalid("%s: %v", k, err)
			}
			val = norm
		}
		set[k] = val
	}
	slices.Sort(remove)
	return set, remove, nil
}

func match(re *regexp.Regexp, v any, want string) error {
	if s, ok := v.(string); ok && re.MatchString(s) {
		return nil
	}
	return fmt.Errorf("must be %s", want)
}

func eachString(v any, check func(string) error) error {
	for _, s := range v.([]string) {
		if err := check(s); err != nil {
			return err
		}
	}
	return nil
}

func checkDomain(s string) error {
	if s != strings.ToLower(s) || len(s) > 253 || !domainRe.MatchString(s) {
		return errors.New("must be a lower-case domain name such as example.com")
	}
	return nil
}

func checkEmail(s string) error {
	at := strings.LastIndexByte(s, '@')
	if at <= 0 || !emailLocal.MatchString(s[:at]) || checkDomain(s[at+1:]) != nil {
		return errors.New("must be an email address such as agent-test@example.com (lower-case domain)")
	}
	return nil
}

// checkURL accepts https URLs, and http only to loopback (local fakes and
// emulators in tests). No credentials, query or fragment.
func checkURL(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return errors.New("must be an absolute URL such as https://host[:port][/path] without credentials or query")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		h := u.Hostname()
		if ip := net.ParseIP(h); h == "localhost" || (ip != nil && ip.IsLoopback()) {
			return nil
		}
		return errors.New("must use https (plain http is allowed only for loopback test endpoints)")
	default:
		return errors.New("must use https")
	}
}

func checkHost(s string) error {
	if ip := net.ParseIP(strings.Trim(s, "[]")); ip != nil {
		return nil
	}
	if !hostRe.MatchString(s) || strings.Contains(s, "..") {
		return errors.New("must be a hostname or IP address")
	}
	return nil
}

func checkPort(n int64) error {
	if n < 1 || n > 65535 {
		return errors.New("must be between 1 and 65535")
	}
	return nil
}

// checkHostPort accepts host:port (an IPv6 literal in brackets).
func checkHostPort(s string) error {
	host, port, err := net.SplitHostPort(s)
	if err != nil || host == "" {
		return errors.New("must be host:port, e.g. temporal.internal:7233")
	}
	if checkHost(host) != nil {
		return errors.New("must be host:port with a valid hostname or IP address")
	}
	n, err := strconv.ParseInt(port, 10, 64)
	if err != nil || checkPort(n) != nil {
		return errors.New("must be host:port with a port between 1 and 65535")
	}
	return nil
}

// checkRedisURL verifies a Celery broker URL: redis:// or rediss://, a host,
// an optional port and database number, and nothing else. Messages never
// contain any part of the value (it may hold a password).
func checkRedisURL(s string) (string, error) {
	s = strings.TrimSpace(s)
	u, err := url.Parse(s)
	if err != nil || u.Opaque != "" || u.Host == "" {
		return "", errors.New("must be a Redis URL such as redis://:password@host:6379/0")
	}
	if u.Scheme != "redis" && u.Scheme != "rediss" {
		return "", errors.New("must use redis:// or rediss:// (TLS)")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("must not contain query options or a fragment")
	}
	if checkHost(u.Hostname()) != nil {
		return "", errors.New("must contain a valid hostname or IP address")
	}
	if p := u.Port(); p != "" {
		n, err := strconv.ParseInt(p, 10, 64)
		if err != nil || checkPort(n) != nil {
			return "", errors.New("port must be between 1 and 65535")
		}
	}
	if db := strings.TrimPrefix(u.Path, "/"); db != "" {
		if n, err := strconv.Atoi(db); err != nil || n < 0 || n > 1<<20 || strconv.Itoa(n) != db {
			return "", errors.New("path must be a database number, e.g. /0")
		}
	}
	return s, nil
}

// checkServiceAccountJSON verifies a Google service account key file: a JSON
// object with type "service_account", a client_email and a private_key that
// parses as an RSA key.
func checkServiceAccountJSON(s string) (string, error) {
	s = strings.TrimSpace(s)
	var sa map[string]any
	dec := json.NewDecoder(strings.NewReader(s))
	if err := dec.Decode(&sa); err != nil || dec.More() || sa == nil {
		return "", errors.New("must be the service account key file (a JSON object)")
	}
	if t, _ := sa["type"].(string); t != "service_account" {
		return "", errors.New(`must have "type": "service_account" (paste a service account key, not an OAuth client file)`)
	}
	email, _ := sa["client_email"].(string)
	if at := strings.LastIndexByte(email, '@'); at <= 0 || at == len(email)-1 {
		return "", errors.New("client_email is missing or not an email address")
	}
	key, _ := sa["private_key"].(string)
	if key == "" {
		return "", errors.New("private_key is missing")
	}
	if _, err := parseRSAPrivateKey(key); err != nil {
		return "", fmt.Errorf("private_key: %v", err)
	}
	if tu, ok := sa["token_uri"]; ok {
		ts, _ := tu.(string)
		if checkURL(ts) != nil {
			return "", errors.New("token_uri must be an https URL")
		}
	}
	return s, nil
}

// checkRSAPrivateKeyPEM verifies a GitHub App private key.
func checkRSAPrivateKeyPEM(s string) (string, error) {
	s = strings.TrimSpace(s)
	if _, err := parseRSAPrivateKey(s); err != nil {
		return "", err
	}
	return s + "\n", nil
}

func parseRSAPrivateKey(s string) (*rsa.PrivateKey, error) {
	block, rest := pem.Decode([]byte(strings.TrimSpace(s)))
	if block == nil {
		return nil, errors.New("must be a PEM private key (-----BEGIN ... PRIVATE KEY-----)")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("must contain exactly one PEM block")
	}
	if _, encrypted := block.Headers["Proc-Type"]; encrypted || block.Type == "ENCRYPTED PRIVATE KEY" {
		return nil, errors.New("encrypted private keys are not supported; paste the unencrypted key")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.New("not a valid RSA private key")
		}
		return k, nil
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.New("not a valid PKCS#8 private key")
		}
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("must be an RSA key")
		}
		return rk, nil
	default:
		return nil, errors.New("must be a PEM private key (-----BEGIN RSA PRIVATE KEY----- or -----BEGIN PRIVATE KEY-----)")
	}
}
