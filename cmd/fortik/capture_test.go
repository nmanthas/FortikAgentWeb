package main

import (
	"testing"

	"fortik/internal/config"
	"fortik/internal/policy"
)

// Policy input capture is refused unless every enabled listener is loopback.
func TestCaptureAllowedOnlyOnLoopback(t *testing.T) {
	cfg := &config.Config{}
	cfg.API.Enabled, cfg.API.Listen = true, "127.0.0.1:8080"
	cfg.Gateway.Enabled, cfg.Gateway.Listen = true, "0.0.0.0:8090"
	t.Setenv(policy.CaptureEnv, "")
	if err := captureAllowed(cfg); err != nil {
		t.Fatalf("capture off: %v", err)
	}
	t.Setenv(policy.CaptureEnv, t.TempDir()+"/cap.jsonl")
	if err := captureAllowed(cfg); err == nil {
		t.Fatal("capture with a non-loopback gateway must be refused")
	}
	cfg.Gateway.Listen = "localhost:8090"
	if err := captureAllowed(cfg); err != nil {
		t.Fatalf("all loopback: %v", err)
	}
}
