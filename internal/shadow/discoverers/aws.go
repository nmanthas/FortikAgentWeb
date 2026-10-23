package discoverers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/smithy-go"

	"fortik/internal/integrations"
	"fortik/internal/shadow"
)

// AWS discovers IAM users with active access keys (ListUsers,
// ListAccessKeys, GetAccessKeyLastUsed) with the credentials of the
// configured "aws" integration. Fortik's own IAM user (the owner of the
// integration's access key) is excluded.
type AWS struct {
	src      integrations.Source
	hc       *http.Client
	maxUsers int
	log      *slog.Logger
}

// NewAWS returns the AWS discoverer and revoker. hc may be nil.
func NewAWS(src integrations.Source, hc *http.Client, log *slog.Logger) *AWS {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &AWS{src: src, hc: hc, maxUsers: 5000, log: log.With("component", "shadow-aws")}
}

func (a *AWS) System() string { return shadow.SystemAWS }

const awsKey = "aws"

var awsRegion = regexp.MustCompile(`^[a-z]{2}(?:-[a-z]+)+-[0-9]{1,2}$`)

type awsSettings struct {
	region, endpoint, keyID, secret string
}

func (a *AWS) settings(ctx context.Context) (awsSettings, *shadow.ScanResult) {
	res := &shadow.ScanResult{System: shadow.SystemAWS, Integration: awsKey}
	if a.src == nil {
		res.Status, res.Detail = shadow.ScanNotConfigured, "no integrations source: not scanned"
		return awsSettings{}, res
	}
	r, err := a.src.Get(ctx, awsKey)
	switch {
	case errors.Is(err, integrations.ErrSecretMissing):
		res.Status, res.Detail = shadow.ScanError, "the aws integration is configured but its access key is missing from the secret store: not scanned"
		return awsSettings{}, res
	case errors.Is(err, integrations.ErrNotConfigured):
		res.Status, res.Detail = shadow.ScanNotConfigured, "the aws integration is not configured: not scanned"
		return awsSettings{}, res
	case err != nil:
		res.Status, res.Detail = shadow.ScanError, "could not read the aws integration: not scanned"
		return awsSettings{}, res
	}
	s := awsSettings{region: strings.TrimSpace(r.Text("region")), endpoint: strings.TrimSpace(r.Text("iam_endpoint")),
		keyID: r.Secret("access_key_id"), secret: r.Secret("secret_access_key")}
	if s.keyID == "" || s.secret == "" {
		res.Status, res.Detail = shadow.ScanNotConfigured, "the aws integration has no access key: not scanned"
		return awsSettings{}, res
	}
	if !awsRegion.MatchString(s.region) {
		res.Status, res.Detail = shadow.ScanError, "the aws integration's region is invalid: not scanned"
		return awsSettings{}, res
	}
	if s.endpoint != "" {
		u, err := url.Parse(s.endpoint)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			res.Status, res.Detail = shadow.ScanError, "the aws integration's iam_endpoint is invalid: not scanned"
			return awsSettings{}, res
		}
	}
	return s, nil
}

func (a *AWS) client(s awsSettings) *iam.Client {
	// IAM is global; it signs in us-east-1 in the commercial partition.
	region := "us-east-1"
	if strings.HasPrefix(s.region, "us-gov-") || strings.HasPrefix(s.region, "cn-") {
		region = s.region
	}
	o := iam.Options{Region: region, Credentials: credentials.NewStaticCredentialsProvider(s.keyID, s.secret, ""), RetryMaxAttempts: 2}
	if s.endpoint != "" {
		o.BaseEndpoint = awssdk.String(s.endpoint)
	}
	if a.hc != nil {
		o.HTTPClient = a.hc
	}
	return iam.New(o)
}

// awsErr reduces an SDK error to its code and message (never signatures or
// credentials).
func awsErr(err error) string {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode() + ": " + shadow.Clean(apiErr.ErrorMessage(), 300)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timed out"
	}
	return "request failed"
}

func tstr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}

// Discover implements shadow.Discoverer.
func (a *AWS) Discover(ctx context.Context) []shadow.ScanResult {
	s, bad := a.settings(ctx)
	if bad != nil {
		return []shadow.ScanResult{*bad}
	}
	res := shadow.ScanResult{System: shadow.SystemAWS, Integration: awsKey}
	c := a.client(s)
	var users []iamtypes.User
	truncated := false
	p := iam.NewListUsersPaginator(c, &iam.ListUsersInput{})
	for p.HasMorePages() {
		out, err := p.NextPage(ctx)
		if err != nil {
			res.Status, res.Detail = shadow.ScanError, "iam:ListUsers failed ("+awsErr(err)+"): not scanned"
			return []shadow.ScanResult{res}
		}
		users = append(users, out.Users...)
		if len(users) >= a.maxUsers {
			truncated = true
			break
		}
	}
	var failures []string
	selfUser := ""
	type keyed struct {
		user iamtypes.User
		key  iamtypes.AccessKeyMetadata
	}
	var active []keyed
	for _, u := range users {
		name := awssdk.ToString(u.UserName)
		kp := iam.NewListAccessKeysPaginator(c, &iam.ListAccessKeysInput{UserName: u.UserName})
		var keys []iamtypes.AccessKeyMetadata
		var kerr error
		for kp.HasMorePages() {
			out, err := kp.NextPage(ctx)
			if err != nil {
				kerr = err
				break
			}
			keys = append(keys, out.AccessKeyMetadata...)
		}
		if kerr != nil {
			failures = append(failures, fmt.Sprintf("iam:ListAccessKeys for %s failed (%s)", name, awsErr(kerr)))
			continue
		}
		self := false
		for _, k := range keys {
			if awssdk.ToString(k.AccessKeyId) == s.keyID {
				self = true
			}
		}
		if self {
			selfUser = name // Fortik's own principal
			continue
		}
		for _, k := range keys {
			if k.Status == iamtypes.StatusTypeActive {
				active = append(active, keyed{u, k})
			}
		}
	}
	for _, kk := range active {
		keyID := awssdk.ToString(kk.key.AccessKeyId)
		name := awssdk.ToString(kk.user.UserName)
		lu, err := c.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{AccessKeyId: kk.key.AccessKeyId})
		ev := map[string]any{"user_name": name, "user_arn": awssdk.ToString(kk.user.Arn), "access_key_id": keyID,
			"key_status": string(kk.key.Status), "key_created": tstr(kk.key.CreateDate), "password_last_used": tstr(kk.user.PasswordLastUsed)}
		if err != nil {
			failures = append(failures, fmt.Sprintf("iam:GetAccessKeyLastUsed for %s failed (%s)", keyID, awsErr(err)))
			ev["last_used"] = "unknown"
		} else if lu.AccessKeyLastUsed != nil {
			ev["last_used"] = tstr(lu.AccessKeyLastUsed.LastUsedDate)
			ev["last_used_service"] = awssdk.ToString(lu.AccessKeyLastUsed.ServiceName)
			ev["last_used_region"] = awssdk.ToString(lu.AccessKeyLastUsed.Region)
		}
		hint := shadow.SoftwareHint(name)
		var why []string
		if kk.user.PasswordLastUsed == nil {
			why = append(why, "the user has never signed in to the console: programmatic access only")
		}
		if hint != "" {
			why = append(why, "the user name suggests automation ("+hint+")")
		}
		software := len(why) > 0
		if software {
			ev["classified_by"] = strings.Join(why, "; ")
		} else {
			ev["classified_by"] = "the user also signs in to the console and the name has no software indicator"
		}
		res.Credentials = append(res.Credentials, shadow.Credential{Kind: shadow.KindIAMUserKey, Ref: keyID, Holder: name,
			Software: software, Integration: awsKey, Label: shadow.Clean("AWS IAM user "+name+" key "+keyID, 200), Evidence: ev})
	}
	notes := []string{fmt.Sprintf("%d IAM user(s), %d active access key(s) outside Fortik", len(users), len(active))}
	if selfUser != "" {
		notes = append(notes, "Fortik's own IAM user "+selfUser+" excluded")
	}
	res.Status = shadow.ScanScanned
	if truncated {
		res.Status = shadow.ScanPartial
		notes = append(notes, fmt.Sprintf("only the first %d users were examined", a.maxUsers))
	}
	if len(failures) > 0 {
		res.Status = shadow.ScanPartial
		if len(failures) > 5 {
			failures = append(failures[:5], fmt.Sprintf("and %d more", len(failures)-5))
		}
		notes = append(notes, failures...)
	}
	res.Detail = strings.Join(notes, "; ")
	return []shadow.ScanResult{res}
}

// Revoke implements shadow.Revoker: deactivates the access key
// (iam:UpdateAccessKey Status=Inactive; reversible, the key is not deleted).
func (a *AWS) Revoke(ctx context.Context, f shadow.Finding) shadow.RevokeResult {
	if f.Kind != shadow.KindIAMUserKey {
		return shadow.RevokeResult{Outcome: shadow.OutcomeManualRequired, Detail: "flagged: revoke it in the AWS console"}
	}
	m := map[string]any{}
	_ = json.Unmarshal(f.Evidence, &m)
	user, _ := m["user_name"].(string)
	if user == "" || f.Holder != user {
		return shadow.RevokeResult{Outcome: shadow.OutcomeNotRevoked, Detail: "the finding does not name the key's IAM user: NOT revoked"}
	}
	s, bad := a.settings(ctx)
	if bad != nil {
		return shadow.RevokeResult{Outcome: shadow.OutcomeNotRevoked, Detail: bad.Detail + " (revoke)"}
	}
	if f.CredentialRef == s.keyID {
		return shadow.RevokeResult{Outcome: shadow.OutcomeNotRevoked, Detail: "this is Fortik's own access key: refused"}
	}
	_, err := a.client(s).UpdateAccessKey(ctx, &iam.UpdateAccessKeyInput{AccessKeyId: awssdk.String(f.CredentialRef),
		UserName: awssdk.String(user), Status: iamtypes.StatusTypeInactive})
	if err != nil {
		return shadow.RevokeResult{Outcome: shadow.OutcomeNotRevoked, Detail: fmt.Sprintf(
			"iam:UpdateAccessKey failed (%s): NOT revoked; deactivate key %s of %s in the AWS console (IAM > Users > %s > Security credentials)",
			awsErr(err), f.CredentialRef, user, user)}
	}
	return shadow.RevokeResult{Outcome: shadow.OutcomeRevoked, Detail: fmt.Sprintf("access key %s of IAM user %s deactivated (Inactive, not deleted)", f.CredentialRef, user)}
}
