package main

import (
	"errors"
	"flag"
	"fmt"

	"fortik/internal/config"
)

// cmdConfig: fortik config check -config F — parses and validates a config
// file (unknown keys, bad modes, missing required settings) without starting
// anything; ${VAR} values are expanded from the environment.
func cmdConfig(args []string) error {
	if len(args) == 0 || args[0] != "check" {
		return errors.New("config: want 'check' (-config FILE)")
	}
	fs := flag.NewFlagSet("config check", flag.ExitOnError)
	p := fs.String("config", "fortik.yaml", "config file")
	_ = fs.Parse(args[1:])
	c, err := config.Load(*p)
	if err != nil {
		return err
	}
	fmt.Printf("%s: valid (enforcement %s, api %s, gateway %v, pgproxy %v, agentgw %v, connectors %v)\n", *p, c.Enforcement.Mode,
		c.API.Listen, c.Gateway.Enabled, c.PGProxy.Enabled, c.AgentGW.Enabled, c.Connectors.Enabled)
	return nil
}
