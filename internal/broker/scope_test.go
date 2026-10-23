package broker_test

import (
	"errors"
	"testing"

	"fortik/internal/access"
	"fortik/internal/action"
	"fortik/internal/broker"
)

func TestAWSVerb(t *testing.T) {
	cases := []struct {
		action string
		cost   float64
		want   action.Verb
	}{
		{"GetObject", 0, action.VerbRead},
		{"ListBuckets", 0, action.VerbRead},
		{"DescribeInstances", 0, action.VerbRead},
		{"HeadObject", 0, action.VerbRead},
		{"BatchGetItem", 0, action.VerbRead},
		{"getobject", 0, action.VerbRead},
		{"GetObject", 50, action.VerbRead},
		{"DeleteObject", 0, action.VerbDelete},
		{"TerminateInstances", 10, action.VerbDelete},
		{"RemoveTags", 0, action.VerbDelete},
		{"PurgeQueue", 0, action.VerbDelete},
		{"DestroyCluster", 0, action.VerbDelete},
		{"DeregisterImage", 0, action.VerbDelete},
		{"RunInstances", 12.5, action.VerbSpend},
		{"PutObject", 1, action.VerbSpend},
		{"PutObject", 0, action.VerbWrite},
		{"CreateBucket", 0, action.VerbWrite},
		{"UpdateItem", 0, action.VerbWrite},
		{"ModifyInstanceAttribute", 0, action.VerbWrite},
		{"AttachVolume", 0, action.VerbWrite},
		{"AddPermission", 0, action.VerbWrite},
		{"SetQueueAttributes", 0, action.VerbWrite},
		{"TagResource", 0, action.VerbWrite},
		{"RunInstances", 0, action.VerbExecute},
		{"Invoke", 0, action.VerbExecute},
		{"Query", 0, action.VerbExecute},
	}
	for _, c := range cases {
		if got := broker.AWSVerb(c.action, c.cost); got != c.want {
			t.Errorf("%s cost=%v: got %s want %s", c.action, c.cost, got, c.want)
		}
	}
}

func TestMatchIAMGlob(t *testing.T) {
	cases := []struct {
		pattern, action string
		want            bool
	}{
		{"*", "s3:GetObject", true},
		{"iam:*", "iam:CreateUser", true},
		{"iam:*", "IAM:createuser", true},
		{"iam:*", "s3:GetObject", false},
		{"s3:delete*", "s3:DeleteObject", true},
		{"s3:delete*", "s3:DeleteObjects", true},
		{"s3:delete*", "s3:GetObject", false},
		{"s3:delete*", "s3:Delete", true},
		{"ec2:terminate?nstances", "ec2:TerminateInstances", true},
		{"ec2:terminate?nstances", "ec2:TerminateNnstances", true},
		{"ec2:terminate?nstances", "ec2:Terminatenstances", false},
		{"*:get*", "dynamodb:GetItem", true},
		{"*object", "s3:PutObject", true},
		{"s3:*object*", "s3:GetObjectAcl", true},
		{"s3:getobject", "s3:GetObjectAcl", false},
		{"", "s3:GetObject", false},
		{"**", "", true},
	}
	for _, c := range cases {
		if got := broker.MatchIAMGlob(c.pattern, c.action); got != c.want {
			t.Errorf("%q vs %q: got %v want %v", c.pattern, c.action, got, c.want)
		}
	}
}

func TestCheckAWSProfile(t *testing.T) {
	rw := access.AWSProfile{Mode: "read_write", Services: []string{"ec2", "s3"}, DeniedActions: []string{"s3:delete*"}}
	ro := access.AWSProfile{Mode: "read_only", Services: []string{"s3"}}
	none := access.AWSProfile{Mode: "none", Services: []string{"s3"}}
	ok := []struct {
		p           access.AWSProfile
		svc, action string
	}{
		{rw, "s3", "PutObject"}, {rw, "ec2", "RunInstances"}, {ro, "s3", "GetObject"}, {ro, "s3", "ListBucket"},
	}
	for _, c := range ok {
		if err := broker.CheckAWSProfile(c.p, c.svc, c.action); err != nil {
			t.Errorf("%s:%s on %+v: %v", c.svc, c.action, c.p, err)
		}
	}
	bad := []struct {
		p           access.AWSProfile
		svc, action string
	}{
		{rw, "s3", "DeleteObject"}, {rw, "dynamodb", "GetItem"}, {ro, "s3", "PutObject"}, {ro, "s3", "Query"},
		{none, "s3", "GetObject"}, {access.AWSProfile{}, "s3", "GetObject"},
	}
	for _, c := range bad {
		if err := broker.CheckAWSProfile(c.p, c.svc, c.action); !errors.Is(err, broker.ErrScopeDenied) {
			t.Errorf("%s:%s on %+v: want ErrScopeDenied, got %v", c.svc, c.action, c.p, err)
		}
	}
}

func TestProfileFromScope(t *testing.T) {
	if _, err := broker.ProfileFromScope("aws", map[string]any{}); !errors.Is(err, broker.ErrScopeDenied) {
		t.Fatalf("missing: %v", err)
	}
	if _, err := broker.ProfileFromScope("aws", map[string]any{broker.ScopeProfile: `{"mode":"x"}`}); !errors.Is(err, broker.ErrScopeDenied) {
		t.Fatalf("invalid: %v", err)
	}
	p, err := broker.ProfileFromScope("aws", map[string]any{broker.ScopeProfile: []byte(`{"mode":"read_only","services":["s3"]}`)})
	if err != nil || p.(access.AWSProfile).Mode != "read_only" {
		t.Fatalf("got %+v %v", p, err)
	}
}

func TestNotConfiguredErrorIs(t *testing.T) {
	var err error = &broker.NotConfiguredError{System: "aws", ActionID: "act_1"}
	if !errors.Is(err, broker.ErrNotConfigured) || err.Error() != "integration not configured: aws" {
		t.Fatalf("got %v", err)
	}
}

func TestCheckAWSProfileRefusesSTSCredentialMinting(t *testing.T) {
	p := access.AWSProfile{Mode: access.ModeReadWrite, Services: []string{"sts"}}
	for _, a := range []string{"AssumeRole", "assumerole", "GetSessionToken", "GetFederationToken", "AssumeRoleWithWebIdentity"} {
		if err := broker.CheckAWSProfile(p, "sts", a); !errors.Is(err, broker.ErrScopeDenied) {
			t.Errorf("sts:%s must be refused, got %v", a, err)
		}
	}
	if err := broker.CheckAWSProfile(p, "sts", "GetCallerIdentity"); err != nil {
		t.Errorf("sts:GetCallerIdentity must stay allowed: %v", err)
	}
}
