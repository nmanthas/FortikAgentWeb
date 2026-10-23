package discoverers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	gh "fortik/internal/broker/github"
	"fortik/internal/integrations"
	"fortik/internal/shadow"
)

func jsonUnmarshal(raw []byte, v any) error { return json.Unmarshal(raw, v) }

// GitHub discovers fine-grained personal access tokens approved for the
// organisation and third-party app installations, through the configured
// GitHub App (installation tokens narrowed to the one org permission each
// listing needs, revoked after use).
type GitHub struct {
	src       integrations.Source
	client    *gh.Client
	knownApps map[string]bool
	maxPages  int
	log       *slog.Logger
}

// NewGitHub returns the GitHub discoverer and revoker. knownApps are app
// slugs the organisation has approved: their installations are recorded as
// known, not flagged.
func NewGitHub(src integrations.Source, client *gh.Client, knownApps []string, log *slog.Logger) *GitHub {
	if client == nil {
		client = gh.NewClient(nil)
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	k := map[string]bool{}
	for _, a := range knownApps {
		if a = strings.ToLower(strings.TrimSpace(a)); a != "" {
			k[a] = true
		}
	}
	return &GitHub{src: src, client: client, knownApps: k, maxPages: 50, log: log.With("component", "shadow-github")}
}

func (g *GitHub) System() string { return shadow.SystemGitHub }

// GitHub App organisation permissions used here.
const (
	permPATs  = "organization_personal_access_tokens"
	permAdmin = "organization_administration"
)

func (g *GitHub) settings(ctx context.Context) (gh.Settings, *shadow.ScanResult) {
	res := &shadow.ScanResult{System: shadow.SystemGitHub, Integration: gh.IntegrationKey}
	if g.src == nil {
		res.Status, res.Detail = shadow.ScanNotConfigured, "no integrations source: not scanned"
		return gh.Settings{}, res
	}
	r, err := g.src.Get(ctx, gh.IntegrationKey)
	switch {
	case errors.Is(err, integrations.ErrSecretMissing):
		res.Status, res.Detail = shadow.ScanError, "the github integration is configured but its private key is missing from the secret store: not scanned"
		return gh.Settings{}, res
	case errors.Is(err, integrations.ErrNotConfigured):
		res.Status, res.Detail = shadow.ScanNotConfigured, "the github integration is not configured: not scanned"
		return gh.Settings{}, res
	case err != nil:
		res.Status, res.Detail = shadow.ScanError, "could not read the github integration: not scanned"
		return gh.Settings{}, res
	}
	s, err := g.client.Settings(r)
	if errors.Is(err, integrations.ErrNotConfigured) {
		res.Status, res.Detail = shadow.ScanNotConfigured, "the github integration is incomplete: not scanned"
		return gh.Settings{}, res
	}
	if err != nil {
		res.Status, res.Detail = shadow.ScanError, shadow.Clean(err.Error(), 300)+": not scanned"
		return gh.Settings{}, res
	}
	return s, nil
}

// withToken mints an installation token holding only perm, runs fn and
// revokes the token.
func (g *GitHub) withToken(ctx context.Context, s gh.Settings, perm, level string, fn func(tok string) error) error {
	tok, err := g.client.MintToken(ctx, s, nil, map[string]string{perm: level})
	if err != nil {
		return fmt.Errorf("the GitHub App could not get %s:%s (%s)", perm, level, shadow.Clean(err.Error(), 300))
	}
	defer func() {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		_ = g.client.RevokeToken(rctx, tok.BaseURL, tok.Secret)
	}()
	return fn(tok.Secret)
}

type ghPAT struct {
	ID    int64 `json:"id"`
	Owner struct {
		Login string `json:"login"`
		Type  string `json:"type"`
	} `json:"owner"`
	RepositorySelection string          `json:"repository_selection"`
	Permissions         json.RawMessage `json:"permissions"`
	AccessGrantedAt     string          `json:"access_granted_at"`
	TokenID             int64           `json:"token_id"`
	TokenName           string          `json:"token_name"`
	TokenExpired        bool            `json:"token_expired"`
	TokenExpiresAt      *string         `json:"token_expires_at"`
	TokenLastUsedAt     *string         `json:"token_last_used_at"`
}

type ghInstallation struct {
	ID      int64  `json:"id"`
	AppID   int64  `json:"app_id"`
	AppSlug string `json:"app_slug"`
	Account struct {
		Login string `json:"login"`
	} `json:"account"`
	TargetType          string            `json:"target_type"`
	RepositorySelection string            `json:"repository_selection"`
	Permissions         map[string]string `json:"permissions"`
	Events              []string          `json:"events"`
	CreatedAt           string            `json:"created_at"`
	UpdatedAt           string            `json:"updated_at"`
	SuspendedAt         *string           `json:"suspended_at"`
}

// Discover implements shadow.Discoverer.
func (g *GitHub) Discover(ctx context.Context) []shadow.ScanResult {
	s, bad := g.settings(ctx)
	if bad != nil {
		return []shadow.ScanResult{*bad}
	}
	res := shadow.ScanResult{System: shadow.SystemGitHub, Integration: gh.IntegrationKey}
	inst, err := g.client.Installation(ctx, s)
	if err != nil {
		res.Status, res.Detail = shadow.ScanError, "could not read the app installation ("+shadow.Clean(err.Error(), 300)+"): not scanned"
		return []shadow.ScanResult{res}
	}
	org := inst.Account
	var notes, failures []string

	// Fine-grained PATs approved for the org.
	patErr := g.withToken(ctx, s, permPATs, "read", func(tok string) error {
		pats, truncated, err := g.listPATs(ctx, s.BaseURL, tok, org)
		if err != nil {
			return err
		}
		for _, p := range pats {
			if p.TokenExpired {
				continue
			}
			res.Credentials = append(res.Credentials, classifyPAT(org, p))
		}
		notes = append(notes, fmt.Sprintf("%d fine-grained PAT(s) approved for %s", len(pats), org))
		if truncated {
			failures = append(failures, fmt.Sprintf("PAT listing stopped after %d pages", g.maxPages))
		}
		return nil
	})
	if patErr != nil {
		failures = append(failures, "fine-grained PATs NOT scanned: "+patErr.Error())
	}

	// App installations on the org.
	instErr := g.withToken(ctx, s, permAdmin, "read", func(tok string) error {
		list, err := g.listInstallations(ctx, s.BaseURL, tok, org)
		if err != nil {
			return err
		}
		n := 0
		for _, in := range list {
			if strconv.FormatInt(in.AppID, 10) == s.AppID || in.SuspendedAt != nil {
				continue // Fortik's own app; suspended installations cannot act
			}
			n++
			res.Credentials = append(res.Credentials, g.classifyInstallation(org, in))
		}
		notes = append(notes, fmt.Sprintf("%d other app installation(s) on %s", n, org))
		return nil
	})
	if instErr != nil {
		failures = append(failures, "app installations NOT scanned: "+instErr.Error())
	}
	switch {
	case patErr != nil && instErr != nil:
		res.Status = shadow.ScanError
	case len(failures) > 0:
		res.Status = shadow.ScanPartial
	default:
		res.Status = shadow.ScanScanned
	}
	notes = append(notes, failures...)
	notes = append(notes, "classic PATs and SSH keys are not listed by the GitHub App API (use the org's credential authorizations or audit log)")
	res.Detail = strings.Join(notes, "; ")
	return []shadow.ScanResult{res}
}

func (g *GitHub) listPATs(ctx context.Context, base, tok, org string) ([]ghPAT, bool, error) {
	var all []ghPAT
	for page := 1; page <= g.maxPages; page++ {
		var batch []ghPAT
		path := "/orgs/" + url.PathEscape(org) + "/personal-access-tokens?per_page=100&page=" + strconv.Itoa(page)
		if _, err := g.client.JSON(ctx, base, tok, http.MethodGet, path, nil, &batch, "list org fine-grained PATs", http.StatusOK); err != nil {
			return nil, false, errors.New(shadow.Clean(err.Error(), 300))
		}
		all = append(all, batch...)
		if len(batch) < 100 {
			return all, false, nil
		}
	}
	return all, true, nil
}

func (g *GitHub) listInstallations(ctx context.Context, base, tok, org string) ([]ghInstallation, error) {
	var all []ghInstallation
	for page := 1; page <= g.maxPages; page++ {
		var resp struct {
			TotalCount    int              `json:"total_count"`
			Installations []ghInstallation `json:"installations"`
		}
		path := "/orgs/" + url.PathEscape(org) + "/installations?per_page=100&page=" + strconv.Itoa(page)
		if _, err := g.client.JSON(ctx, base, tok, http.MethodGet, path, nil, &resp, "list org app installations", http.StatusOK); err != nil {
			return nil, errors.New(shadow.Clean(err.Error(), 300))
		}
		all = append(all, resp.Installations...)
		if len(resp.Installations) < 100 || len(all) >= resp.TotalCount {
			break
		}
	}
	return all, nil
}

func strp(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

func classifyPAT(org string, p ghPAT) shadow.Credential {
	nameHint := shadow.SoftwareHint(p.TokenName)
	ownerHint := shadow.SoftwareHint(p.Owner.Login)
	var why []string
	if strings.EqualFold(p.Owner.Type, "Bot") {
		why = append(why, "the token's owner is a bot account")
	}
	if nameHint != "" {
		why = append(why, "the token name suggests automation ("+nameHint+")")
	}
	if ownerHint != "" {
		why = append(why, "the owner's login suggests a machine user ("+ownerHint+")")
	}
	software := len(why) > 0
	reason := strings.Join(why, "; ")
	if !software {
		reason = "no software indicator (GitHub does not expose the token's user agent to apps)"
	}
	var perms any
	if len(p.Permissions) > 0 && len(p.Permissions) < 8<<10 {
		_ = json.Unmarshal(p.Permissions, &perms)
	}
	ev := map[string]any{
		"org": org, "pat_id": p.ID, "token_id": p.TokenID, "token_name": shadow.Clean(p.TokenName, 120),
		"owner": p.Owner.Login, "owner_type": p.Owner.Type, "repository_selection": p.RepositorySelection,
		"permissions": perms, "access_granted_at": p.AccessGrantedAt, "token_expires_at": strp(p.TokenExpiresAt),
		"token_last_used_at": strp(p.TokenLastUsedAt), "classified_by": reason,
	}
	if p.TokenExpiresAt == nil {
		ev["never_expires"] = true
	}
	return shadow.Credential{Kind: shadow.KindPAT, Ref: "pat:" + strconv.FormatInt(p.TokenID, 10), Holder: p.Owner.Login,
		Software: software, Integration: gh.IntegrationKey,
		Label: shadow.Clean("GitHub PAT "+p.TokenName+" of "+p.Owner.Login, 200), Evidence: ev}
}

func (g *GitHub) classifyInstallation(org string, in ghInstallation) shadow.Credential {
	known := g.knownApps[strings.ToLower(in.AppSlug)]
	reason := "a GitHub App acts as software; it is not registered with Fortik"
	if known {
		reason = "app is on the approved list (shadow.github_known_apps)"
	}
	perms := map[string]any{}
	keys := make([]string, 0, len(in.Permissions))
	for k := range in.Permissions {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		perms[k] = in.Permissions[k]
	}
	ev := map[string]any{
		"org": org, "installation_id": in.ID, "app_id": in.AppID, "app_slug": in.AppSlug, "target_type": in.TargetType,
		"repository_selection": in.RepositorySelection, "permissions": perms, "events": limit(in.Events, 20),
		"created_at": in.CreatedAt, "updated_at": in.UpdatedAt, "classified_by": reason,
	}
	return shadow.Credential{Kind: shadow.KindAppInstallation, Ref: "installation:" + strconv.FormatInt(in.ID, 10),
		Holder: in.AppSlug, Software: !known, Integration: gh.IntegrationKey,
		Label: shadow.Clean("GitHub app "+in.AppSlug, 200), Evidence: ev}
}

// Revoke implements shadow.Revoker. A fine-grained PAT's org access is
// revoked through the org PAT API (needs the app's
// organization_personal_access_tokens:write); an app installation can only
// be removed by an org owner.
func (g *GitHub) Revoke(ctx context.Context, f shadow.Finding) shadow.RevokeResult {
	m := map[string]any{}
	_ = json.Unmarshal(f.Evidence, &m)
	org, _ := m["org"].(string)
	switch f.Kind {
	case shadow.KindAppInstallation:
		return shadow.RevokeResult{Outcome: shadow.OutcomeManualRequired, Detail: fmt.Sprintf(
			"flagged: an app installation can only be removed by an org owner; uninstall %q in GitHub > %s > Settings > GitHub Apps", f.Holder, org)}
	case shadow.KindPAT:
	default:
		return shadow.RevokeResult{Outcome: shadow.OutcomeManualRequired, Detail: "flagged: revoke it in the GitHub console"}
	}
	patID, ok := m["pat_id"].(float64)
	if !ok || patID <= 0 || patID != float64(int64(patID)) {
		return shadow.RevokeResult{Outcome: shadow.OutcomeNotRevoked, Detail: "the finding has no PAT grant id: NOT revoked"}
	}
	s, bad := g.settings(ctx)
	if bad != nil {
		return shadow.RevokeResult{Outcome: shadow.OutcomeNotRevoked, Detail: bad.Detail + " (revoke)"}
	}
	inst, err := g.client.Installation(ctx, s)
	if err != nil {
		return shadow.RevokeResult{Outcome: shadow.OutcomeNotRevoked, Detail: "could not read the app installation: NOT revoked"}
	}
	if org == "" || !strings.EqualFold(inst.Account, org) {
		return shadow.RevokeResult{Outcome: shadow.OutcomeNotRevoked, Detail: "the finding's org is not the configured installation's account: NOT revoked"}
	}
	err = g.withToken(ctx, s, permPATs, "write", func(tok string) error {
		path := "/orgs/" + url.PathEscape(org) + "/personal-access-tokens/" + strconv.FormatInt(int64(patID), 10)
		_, err := g.client.JSON(ctx, s.BaseURL, tok, http.MethodPost, path, map[string]string{"action": "revoke"}, nil,
			"revoke fine-grained PAT", http.StatusNoContent, http.StatusAccepted)
		return err
	})
	if err != nil {
		return shadow.RevokeResult{Outcome: shadow.OutcomeNotRevoked, Detail: fmt.Sprintf(
			"NOT revoked (%s); revoke the token's access in GitHub > %s > Settings > Personal access tokens > Active tokens",
			shadow.Clean(err.Error(), 300), org)}
	}
	return shadow.RevokeResult{Outcome: shadow.OutcomeRevoked, Detail: fmt.Sprintf(
		"GitHub revoked %s's fine-grained PAT %q (grant %d) access to %s", f.Holder, m["token_name"], int64(patID), org)}
}
