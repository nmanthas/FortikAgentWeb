package aws_test

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"

	brokeraws "fortik/internal/broker/aws"
)

// EnvMoto points at a moto server (a LOCAL FAKE of AWS, `moto_server -p
// <port>`) for tests where the real API shapes matter: the SDK talks to it
// exactly as it would to AWS. Skipped (with this message) when unset.
const EnvMoto = "FORTIK_TEST_MOTO_URL"

func motoURL(t *testing.T) string {
	t.Helper()
	u := os.Getenv(EnvMoto)
	if u == "" {
		t.Skipf("moto test skipped: set %s to a running moto_server URL", EnvMoto)
	}
	return u
}

// TestAgainstMoto runs Mint, RevokeAgent and the connection Tester against
// moto's STS and IAM: the role is created in moto, the session is assumed,
// and the revocation policy is read back from IAM.
func TestAgainstMoto(t *testing.T) {
	endpoint := motoURL(t)
	ctx := context.Background()
	roleName := "fortik-agents-" + time.Now().Format("150405.000000")
	roleName = strings.ReplaceAll(roleName, ".", "")
	admin := iam.New(iam.Options{Region: "us-east-1", BaseEndpoint: awssdk.String(endpoint),
		Credentials: credentials.NewStaticCredentialsProvider(fortikKey, fortikSecret, "")})
	trust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":["sts:AssumeRole","sts:SetSourceIdentity"]}]}`
	created, err := admin.CreateRole(ctx, &iam.CreateRoleInput{RoleName: awssdk.String(roleName), Path: awssdk.String("/agents/"),
		AssumeRolePolicyDocument: awssdk.String(trust)})
	if err != nil {
		t.Fatalf("moto CreateRole: %v", err)
	}
	r := resolved(endpoint, nil)
	r.ConfigMap["role_arn"] = *created.Role.Arn

	if err := brokeraws.NewTester().Test(ctx, *r); err != nil {
		t.Fatalf("tester: %v", err)
	}

	a := newAdapter(t, &fakeSource{r: r})
	cred, err := a.Mint(ctx, "claude_code_01", scope(rwS3, "s3", "GetObject", "arn:aws:s3:::reports/*", "eu-west-1"), 0)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if cred.Secret["access_key_id"] == "" || cred.Secret["access_key_id"] == fortikKey || cred.Secret["session_token"] == "" {
		t.Fatalf("credential %+v", cred.Secret)
	}
	if d := time.Until(cred.ExpiresAt); d < 14*time.Minute || d > 16*time.Minute {
		t.Fatalf("expires in %s", d)
	}

	if _, err := a.RevokeAgent(ctx, "claude_code_01"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	got, err := admin.GetRolePolicy(ctx, &iam.GetRolePolicyInput{RoleName: awssdk.String(roleName),
		PolicyName: awssdk.String(brokeraws.RevokePolicyName)})
	if err != nil {
		t.Fatalf("GetRolePolicy: %v", err)
	}
	doc := *got.PolicyDocument
	if d, err := url.QueryUnescape(doc); err == nil {
		doc = d // real IAM URL-encodes policy documents
	}
	want := brokeraws.RevokePolicy(map[string]time.Time{"claude_code_01": fixedNow.Add(time.Minute)})
	if strings.ReplaceAll(doc, " ", "") != want {
		t.Fatalf("stored revocation policy\n got %s\nwant %s", doc, want)
	}
}
