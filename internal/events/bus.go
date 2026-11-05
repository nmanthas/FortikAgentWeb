package events

import (
	"context"
	"fmt"
	"log/slog"

	"fortik/internal/config"
	"fortik/internal/tlsx"
)

// New builds the configured bus (events.provider: memory | nats).
func New(ctx context.Context, c config.EventsConfig, log *slog.Logger) (Bus, error) {
	switch c.Provider {
	case "", "memory":
		return NewMemoryBus(DefaultRingSize), nil
	case "nats":
		o := NATSOptions{Log: log}
		if c.TLSCAFile != "" || c.TLSCertFile != "" || c.TLSKeyFile != "" {
			tc, err := tlsx.Client(c.TLSCAFile, c.TLSCertFile, c.TLSKeyFile)
			if err != nil {
				return nil, fmt.Errorf("events: %w", err)
			}
			o.TLS = tc
		}
		return NewNATSBus(ctx, c.URL, o)
	default:
		return nil, fmt.Errorf("events: unknown provider %q", c.Provider)
	}
}
