package aws_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"fortik/internal/integrations"
)

// fakeAWS is a LOCAL FAKE of the subset of the AWS STS and IAM query APIs
// the adapter uses (STS AssumeRole and GetCallerIdentity, IAM PutRolePolicy).
// It is not AWS: it records each request's form values and SigV4 access key
// so tests can assert exactly what Fortik sent, and answers with the XML
// shapes the SDK parses.
type fakeAWS struct {
	srv *httptest.Server

	mu       sync.Mutex
	calls    []fakeCall
	failWith string            // when set, every call fails with this AWS error code
	policies map[string]string // role/policy -> document (PutRolePolicy / GetRolePolicy)
}

type fakeCall struct {
	Action        string
	Form          url.Values
	AccessKey     string // from the SigV4 Authorization header
	SecurityToken string
}

const (
	fakeSessionKey    = "ASIAFAKESESSIONKEY01"
	fakeSessionSecret = "fake-session-secret"
	fakeSessionToken  = "fake-session-token"
)

func newFakeAWS(t *testing.T) *fakeAWS {
	t.Helper()
	f := &fakeAWS{}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAWS) serve(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	call := fakeCall{Action: r.PostForm.Get("Action"), Form: r.PostForm, SecurityToken: r.Header.Get("X-Amz-Security-Token")}
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=") {
		call.AccessKey = strings.SplitN(strings.TrimPrefix(auth, "AWS4-HMAC-SHA256 Credential="), "/", 2)[0]
	}
	f.mu.Lock()
	f.calls = append(f.calls, call)
	fail := f.failWith
	f.mu.Unlock()

	w.Header().Set("Content-Type", "text/xml")
	if fail != "" {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, `<ErrorResponse><Error><Type>Sender</Type><Code>%s</Code><Message>User is not authorized to perform this operation</Message></Error><RequestId>req-1</RequestId></ErrorResponse>`, fail)
		return
	}
	switch call.Action {
	case "AssumeRole":
		dur := r.PostForm.Get("DurationSeconds")
		var secs int
		fmt.Sscan(dur, &secs)
		exp := time.Now().UTC().Add(time.Duration(secs) * time.Second).Format(time.RFC3339)
		fmt.Fprintf(w, `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult>
<SourceIdentity>%s</SourceIdentity>
<AssumedRoleUser><Arn>arn:aws:sts::123456789012:assumed-role/fortik-agents/%s</Arn><AssumedRoleId>AROAFAKE:%s</AssumedRoleId></AssumedRoleUser>
<Credentials><AccessKeyId>%s</AccessKeyId><SecretAccessKey>%s</SecretAccessKey><SessionToken>%s</SessionToken><Expiration>%s</Expiration></Credentials>
</AssumeRoleResult><ResponseMetadata><RequestId>req-2</RequestId></ResponseMetadata></AssumeRoleResponse>`,
			r.PostForm.Get("SourceIdentity"), r.PostForm.Get("RoleSessionName"), r.PostForm.Get("RoleSessionName"),
			fakeSessionKey, fakeSessionSecret, fakeSessionToken, exp)
	case "GetCallerIdentity":
		fmt.Fprint(w, `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult>
<Arn>arn:aws:sts::123456789012:assumed-role/fortik-agents/test</Arn><UserId>AROAFAKE:test</UserId><Account>123456789012</Account>
</GetCallerIdentityResult><ResponseMetadata><RequestId>req-3</RequestId></ResponseMetadata></GetCallerIdentityResponse>`)
	case "GetRolePolicy":
		f.mu.Lock()
		doc, ok := f.policies[r.PostForm.Get("RoleName")+"/"+r.PostForm.Get("PolicyName")]
		f.mu.Unlock()
		if !ok {
			w.WriteHeader(404)
			fmt.Fprint(w, `<ErrorResponse><Error><Type>Sender</Type><Code>NoSuchEntity</Code><Message>not found</Message></Error></ErrorResponse>`)
			return
		}
		fmt.Fprintf(w, `<GetRolePolicyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><GetRolePolicyResult><RoleName>%s</RoleName><PolicyName>%s</PolicyName><PolicyDocument>%s</PolicyDocument></GetRolePolicyResult></GetRolePolicyResponse>`,
			r.PostForm.Get("RoleName"), r.PostForm.Get("PolicyName"), url.QueryEscape(doc))
	case "PutRolePolicy":
		f.mu.Lock()
		if f.policies == nil {
			f.policies = map[string]string{}
		}
		f.policies[r.PostForm.Get("RoleName")+"/"+r.PostForm.Get("PolicyName")] = r.PostForm.Get("PolicyDocument")
		f.mu.Unlock()
		fmt.Fprint(w, `<PutRolePolicyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><ResponseMetadata><RequestId>req-4</RequestId></ResponseMetadata></PutRolePolicyResponse>`)
	default:
		w.WriteHeader(400)
		fmt.Fprintf(w, `<ErrorResponse><Error><Type>Sender</Type><Code>InvalidAction</Code><Message>fake does not implement %s</Message></Error></ErrorResponse>`, call.Action)
	}
}

func (f *fakeAWS) all() []fakeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeCall(nil), f.calls...)
}

// fakeSource is a LOCAL FAKE integrations.Source holding one resolved "aws"
// integration (or none).
type fakeSource struct {
	r   *integrations.Resolved
	err error
}

func (s *fakeSource) Get(_ context.Context, key string) (integrations.Resolved, error) {
	if s.err != nil {
		return integrations.Resolved{}, s.err
	}
	if s.r == nil || key != s.r.Key {
		return integrations.Resolved{}, integrations.ErrNotConfigured
	}
	return *s.r, nil
}

func (s *fakeSource) List(ctx context.Context, system string) ([]integrations.Resolved, error) {
	r, err := s.Get(ctx, system)
	if err != nil {
		return nil, nil
	}
	return []integrations.Resolved{r}, nil
}

const (
	fortikKey    = "AKIAFORTIKFAKEKEY001"
	fortikSecret = "fortik-long-lived-secret-never-leaves"
	roleARN      = "arn:aws:iam::123456789012:role/agents/fortik-agents"
)

func resolved(endpoint string, extra map[string]string) *integrations.Resolved {
	secrets := map[string]string{"access_key_id": fortikKey, "secret_access_key": fortikSecret}
	for k, v := range extra {
		secrets[k] = v
	}
	return &integrations.Resolved{
		Integration: integrations.Integration{Key: "aws", System: "aws", Status: "configured"},
		ConfigMap: map[string]any{"region": "eu-west-1", "role_arn": roleARN,
			"sts_endpoint": endpoint, "iam_endpoint": endpoint},
		Secrets: secrets,
	}
}
