package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fortik/internal/tlsx"
)

// cmdCerts: fortik certs dev -out DIR [-hosts h1,h2] [-clients c1,c2]
// writes a development CA, server and client certificates for mTLS between
// Fortik and its callers (local and Docker Compose only).
func cmdCerts(args []string) error {
	if len(args) == 0 || args[0] != "dev" {
		return errors.New("certs: want 'dev' (-out DIR [-hosts localhost,127.0.0.1,fortik] [-clients hook,interceptor,agentgateway])")
	}
	fs := flag.NewFlagSet("certs dev", flag.ExitOnError)
	out := fs.String("out", ".dev/tls", "output directory")
	hosts := fs.String("hosts", "localhost,127.0.0.1,fortik", "server certificate names (DNS or IP)")
	clients := fs.String("clients", "hook,interceptor,agentgateway,console-proxy", "client certificate names")
	days := fs.Int("days", 365, "validity in days")
	ifAbsent := fs.Bool("if-absent", false, "do nothing (exit 0) when -out already holds a CA")
	_ = fs.Parse(args[1:])
	if *ifAbsent {
		if _, err := os.Stat(filepath.Join(*out, "ca.crt")); err == nil {
			fmt.Printf("development PKI already in %s: kept\n", *out)
			return nil
		}
	}
	files, err := tlsx.DevCerts(*out, split(*hosts), split(*clients), time.Duration(*days)*24*time.Hour)
	if err != nil {
		return err
	}
	fmt.Printf("development PKI written to %s (never use in production): %s\n", *out, strings.Join(files, " "))
	return nil
}

func split(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
