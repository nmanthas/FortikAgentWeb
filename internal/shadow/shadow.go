// Package shadow implements shadow-agent discovery (docs/PHASE5_DESIGN.md §3):
// standing credentials found in the systems Fortik brokers (Postgres login
// roles, GitHub fine-grained PATs and app installations, AWS IAM access keys,
// Google Workspace OAuth grants) and unknown callers seen on Fortik's own
// authentication paths (gateway, hook, pgproxy).
//
// A credential used by software rather than a person becomes a DISCOVERED
// agent: registered with discovered=true, no owner (sponsor ”) and level
// ISOLATED, and its finding is flagged for revocation. Security then
// revokes the credential where Fortik can, dismisses the finding, or
// registers the agent properly with an owner.
//
// This is a DEFENSIVE component. Findings carry identifiers only (role
// names, key ids, token ids, client ids, keyed hash prefixes of unknown
// bearer tokens), never a secret. Discoverers are read-only except for an
// explicit, security-approved revoke.
package shadow

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"
)

// Systems (shadow_findings.system).
const (
	SystemPostgres = "postgres"
	SystemGitHub   = "github"
	SystemAWS      = "aws"
	SystemGoogle   = "google_workspace"
	SystemTraffic  = "traffic"
)

// Kinds (shadow_findings.kind).
const (
	KindDBRole             = "db_role"
	KindPAT                = "pat"
	KindAppInstallation    = "app_installation"
	KindIAMUserKey         = "iam_user_key"
	KindOAuthGrant         = "oauth_grant"
	KindUnknownToken       = "unknown_token"
	KindUnknownAgent       = "unknown_agent"
	KindUnknownHost        = "unknown_host"
	KindUnknownOAuthClient = "unknown_oauth_client"
)

// Statuses (shadow_findings.status).
const (
	StatusOpen       = "open"
	StatusFlagged    = "flagged_for_revocation"
	StatusRevoked    = "revoked"
	StatusDismissed  = "dismissed"
	StatusRegistered = "registered"
)

// Scan statuses of one system or integration.
const (
	ScanScanned       = "scanned"        // listed completely
	ScanPartial       = "partial"        // some sub-listing failed; what was found is applied
	ScanNotConfigured = "not_configured" // integration missing: NOT scanned (never "nothing found")
	ScanError         = "error"          // NOT scanned
)

// Revoke outcomes.
const (
	OutcomeRevoked        = "revoked"         // Fortik revoked it and verified the call succeeded
	OutcomeNotRevoked     = "not_revoked"     // Fortik tried and failed; the credential is still live
	OutcomeManualRequired = "manual_required" // Fortik cannot revoke it; do it in the system's console
)

// Diary event types.
const (
	EventFound         = "shadow.found"
	EventAgentFound    = "agent.discovered"
	EventRevoked       = "shadow.revoked"
	EventRevokeFailed  = "shadow.revoke_failed"
	EventDismissed     = "shadow.dismissed"
	EventRegistered    = "shadow.registered"
	EventScanned       = "shadow.scanned"
	AlertKindShadow    = "shadow_agent"
	AgentTypeShadow    = "discovered"
	actorScanner       = "system:shadow"
	actorTraffic       = "system:shadow-traffic"
	maxEvidenceBytes   = 16 << 10
	maxRefLen          = 256
	maxHolderLen       = 256
	defaultScanTimeout = 5 * time.Minute
)

var (
	// ErrNotFound: no such finding.
	ErrNotFound = errors.New("shadow finding not found")
	// ErrState: the finding's status does not allow the action.
	ErrState = errors.New("shadow finding state does not allow this action")
	// ErrInvalid: a malformed request.
	ErrInvalid = errors.New("invalid shadow request")
	// ErrScanRunning: a scan is already in progress.
	ErrScanRunning = errors.New("a shadow scan is already running")
	// ErrAgentConflict: the deterministic discovered-agent id is taken by an
	// agent that was not discovered (never hijacked).
	ErrAgentConflict = errors.New("discovered agent id is already used by a registered agent")
	// ErrNotRecorded: an action reached the upstream system but its outcome
	// could not be written to Postgres/Diary. The message says what happened.
	ErrNotRecorded = errors.New("shadow: outcome could not be recorded")
)

var kindPattern = regexp.MustCompile(`^[a-z][a-z_]{0,63}$`)

// Finding is one row of shadow_findings.
type Finding struct {
	FindingID      string          `json:"finding_id"`
	System         string          `json:"system"`
	Kind           string          `json:"kind"`
	CredentialRef  string          `json:"credential_id"`
	Holder         string          `json:"holder"`
	UsedBySoftware bool            `json:"used_by_software"`
	Evidence       json.RawMessage `json:"evidence"`
	AgentID        string          `json:"discovered_agent_id,omitempty"`
	Status         string          `json:"status"`
	FirstSeen      time.Time       `json:"created_at"`
	LastSeen       time.Time       `json:"last_seen"`
	UpdatedBy      string          `json:"updated_by,omitempty"`
}

// Credential is one standing credential (or unknown caller) a discoverer
// reports. Ref is an identifier and never the secret itself.
type Credential struct {
	Kind     string
	Ref      string
	Holder   string
	Software bool
	// Integration is the integration key the credential lives behind
	// ("postgres:acme_prod", "github"...), recorded in the evidence so a
	// revoke reaches the same system.
	Integration string
	// Label names the discovered agent ("postgres role nightly_sync_script").
	Label    string
	Evidence map[string]any
}

// ScanResult is the honest outcome of scanning one system or integration.
type ScanResult struct {
	System      string       `json:"system"`
	Integration string       `json:"integration,omitempty"`
	Status      string       `json:"status"`
	Detail      string       `json:"detail,omitempty"`
	Credentials []Credential `json:"-"`
	Found       int          `json:"credentials"`
	Software    int          `json:"used_by_software"`
	New         int          `json:"new_findings"`
	Flagged     int          `json:"newly_flagged"`
	Failed      int          `json:"not_recorded,omitempty"`
}

// Report is one scan.
type Report struct {
	ScanID     string       `json:"scan_id"`
	Actor      string       `json:"actor"`
	Reason     string       `json:"reason,omitempty"`
	StartedAt  time.Time    `json:"started_at"`
	FinishedAt time.Time    `json:"finished_at"`
	Systems    []ScanResult `json:"systems"`
	Found      int          `json:"credentials"`
	Software   int          `json:"used_by_software"`
	New        int          `json:"new_findings"`
	Flagged    int          `json:"newly_flagged"`
	NotScanned []string     `json:"not_scanned"`
}

// RevokeResult is what a revoker achieved.
type RevokeResult struct {
	Outcome string `json:"outcome"`
	Detail  string `json:"detail"`
}

// Discoverer lists the standing credentials of one system. It returns one
// ScanResult per integration it covers (Postgres: one per postgres:*
// upstream). A system that is not configured must be reported as
// ScanNotConfigured, never as an empty scan.
type Discoverer interface {
	System() string
	Discover(ctx context.Context) []ScanResult
}

// Revoker revokes a finding's credential where Fortik can. It must never
// claim success it did not verify.
type Revoker interface {
	System() string
	Revoke(ctx context.Context, f Finding) RevokeResult
}

// ---- identifiers ----

func shortHash(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// FindingID is the deterministic id of (system, kind, ref).
func FindingID(system, kind, ref string) string {
	return "shf_" + shortHash("finding", system, kind, ref)[:16]
}

var findingIDPattern = regexp.MustCompile(`^shf_[0-9a-f]{16}$`)

// ValidFindingID reports whether id can be a finding id.
func ValidFindingID(id string) bool { return findingIDPattern.MatchString(id) }

var agentSystems = map[string]string{
	SystemPostgres: "postgres", SystemGitHub: "github", SystemAWS: "aws", SystemGoogle: "google", SystemTraffic: "traffic",
}

// AgentID is the deterministic discovered-agent id of a credential:
// shadow_<system>_<10 hex>.
func AgentID(system, kind, ref string) string {
	s, ok := agentSystems[system]
	if !ok {
		s = "other"
	}
	return "shadow_" + s + "_" + shortHash("agent", system, kind, ref)[:10]
}

// tokenRefKey keys TokenRef. Without a server key a reader of the findings
// (any auditor) could confirm a guessed low-entropy secret, such as a
// person's password typed at pgproxy, offline against the stored prefix.
var tokenRefKey atomic.Pointer[[]byte]

func init() {
	// Until SetTokenRefKey is called: a random per-process key (refs are then
	// stable only within one process run, never guessable).
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic("shadow: no randomness for the token-ref key: " + err.Error())
	}
	tokenRefKey.Store(&k)
}

// SetTokenRefKey derives the TokenRef key from a server-held secret (the
// Diary signing key), so refs are stable across restarts and processes and
// cannot be checked without the secret. The secret itself is never used
// directly.
func SetTokenRefKey(secret []byte) {
	if len(secret) == 0 {
		return
	}
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("fortik/shadow/token-ref-key/v1"))
	k := m.Sum(nil)
	tokenRefKey.Store(&k)
}

// TokenRef is the identifier recorded for an unknown bearer token: a 12-hex
// prefix of a keyed, domain-separated HMAC-SHA256. It identifies repeat use
// of the same token without storing it; it is not the token's agent_tokens
// hash and cannot be reversed or dictionary-checked without the server key.
func TokenRef(token string) string {
	m := hmac.New(sha256.New, *tokenRefKey.Load())
	m.Write([]byte("fortik/shadow/token-ref/v1\x00" + token))
	return hex.EncodeToString(m.Sum(nil)[:6])
}

// ---- classification helpers ----

// softwareWords mark a name as belonging to software rather than a person.
var softwareWords = map[string]bool{
	"bot": true, "bots": true, "svc": true, "service": true, "script": true, "scripts": true, "sync": true,
	"etl": true, "cron": true, "job": true, "jobs": true, "batch": true, "pipeline": true, "deploy": true,
	"deployer": true, "ci": true, "cd": true, "automation": true, "automated": true, "integration": true,
	"worker": true, "daemon": true, "agent": true, "robot": true, "api": true, "loader": true,
	"exporter": true, "importer": true, "replicator": true, "backup": true, "scheduler": true, "airflow": true,
	"dbt": true, "fivetran": true, "airbyte": true, "terraform": true, "jenkins": true, "github_actions": true,
	"actions": true, "lambda": true, "nightly": true, "hourly": true, "daily": true, "machine": true,
}

// SoftwareHint returns the words in name that suggest software ("" if none).
func SoftwareHint(name string) string {
	var hits []string
	seen := map[string]bool{}
	for _, w := range strings.FieldsFunc(strings.ToLower(name), func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
	}) {
		if softwareWords[w] && !seen[w] {
			seen[w] = true
			hits = append(hits, w)
		}
	}
	return strings.Join(hits, ",")
}

// Clean drops control characters, makes s valid UTF-8 and clips it to n
// bytes (on a rune boundary). Used for every attacker- or system-supplied
// string that ends up in a finding.
func Clean(s string, n int) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "?")
	}
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > n {
		for n > 0 && !utf8.RuneStart(s[n]) {
			n--
		}
		s = s[:n]
	}
	return s
}
