package events

import (
	"context"
	"fmt"
	"log/slog"

	"fortik/internal/config"
)

// New builds the configured bus (events.provider: memory | nats).
func New(ctx context.Context, c config.EventsConfig, log *slog.Logger) (Bus, error) {
	switch c.Provider {
	case "", "memory":
		return NewMemoryBus(DefaultRingSize), nil
	case "nats":
		return NewNATSBus(ctx, c.URL, NATSOptions{Log: log})
	default:
		return nil, fmt.Errorf("events: unknown provider %q", c.Provider)
	}
}
