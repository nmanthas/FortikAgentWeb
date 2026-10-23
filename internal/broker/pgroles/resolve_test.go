package pgroles

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"fortik/internal/integrations"
)

// fakeRowSource mimics integrations.PGStore: Get reports ErrNotConfigured for
// both a missing row and a row that is unconfigured or missing secrets.
type fakeRowSource struct {
	rowExists bool
	rowErr    error
}

func (f fakeRowSource) Get(ctx context.Context, key string) (integrations.Resolved, error) {
	return integrations.Resolved{}, fmt.Errorf("%w: %s: secret admin_password not set", integrations.ErrNotConfigured, key)
}

func (f fakeRowSource) GetIntegration(ctx context.Context, key string) (integrations.Integration, error) {
	if f.rowErr != nil {
		return integrations.Integration{}, f.rowErr
	}
	if !f.rowExists {
		return integrations.Integration{}, fmt.Errorf("%w: %s", integrations.ErrNotConfigured, key)
	}
	return integrations.Integration{Key: key}, nil
}

// A broken postgres:<name> integration must fail closed, never fall back to
// the YAML static user (ErrUpstreamNotManaged).
func TestResolveBrokenIntegrationFailsClosed(t *testing.T) {
	ctx := context.Background()
	if _, err := Resolve(ctx, fakeRowSource{}, "appdb"); !errors.Is(err, ErrUpstreamNotManaged) {
		t.Fatalf("no row: want ErrUpstreamNotManaged, got %v", err)
	}
	_, err := Resolve(ctx, fakeRowSource{rowExists: true}, "appdb")
	if err == nil || errors.Is(err, ErrUpstreamNotManaged) || !errors.Is(err, integrations.ErrNotConfigured) {
		t.Fatalf("broken row: want fail-closed ErrNotConfigured, got %v", err)
	}
	_, err = Resolve(ctx, fakeRowSource{rowErr: errors.New("db down")}, "appdb")
	if err == nil || errors.Is(err, ErrUpstreamNotManaged) {
		t.Fatalf("row lookup error: want fail closed, got %v", err)
	}
}

func (f fakeRowSource) List(ctx context.Context, system string) ([]integrations.Resolved, error) {
	return nil, nil
}
