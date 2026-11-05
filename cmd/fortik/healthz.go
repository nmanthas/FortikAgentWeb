package main

import (
	"errors"
	"flag"
	"fmt"
	"net/http"
	"time"

	"fortik/internal/tlsx"
)

// cmdHealthz: fortik healthz -url URL [-ca F] [-cert F -key F]
// exits 0 when URL answers 200 (container health checks: the image has no
// shell or curl).
func cmdHealthz(args []string) error {
	fs := flag.NewFlagSet("healthz", flag.ExitOnError)
	u := fs.String("url", "http://127.0.0.1:8080/healthz", "health URL")
	ca := fs.String("ca", "", "CA file for https")
	cert := fs.String("cert", "", "client certificate (mTLS)")
	key := fs.String("key", "", "client key (mTLS)")
	_ = fs.Parse(args)
	cl := &http.Client{Timeout: 3 * time.Second}
	if *ca != "" || *cert != "" {
		tc, err := tlsx.Client(*ca, *cert, *key)
		if err != nil {
			return err
		}
		cl.Transport = &http.Transport{TLSClientConfig: tc}
	}
	res, err := cl.Get(*u)
	if err != nil {
		return err
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return errors.New(res.Status)
	}
	fmt.Println("ok")
	return nil
}
