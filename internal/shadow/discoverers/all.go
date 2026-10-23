package discoverers

import (
	"errors"
	"log/slog"
	"net/http"

	gh "fortik/internal/broker/github"
	"fortik/internal/integrations"
	"fortik/internal/shadow"
)

// Config wires every discoverer.
type Config struct {
	// Integrations is the console-configured integrations source
	// (*integrations.PGStore). Required.
	Integrations integrations.Source
	// GitHub is the shared GitHub App client (nil: a new one).
	GitHub *gh.Client
	// HTTPClient is used for AWS and Google calls (nil: defaults).
	HTTPClient *http.Client
	// GoogleTokenURL and GoogleAdminBaseURL override Google's endpoints
	// (local fakes only); empty = Google.
	GoogleTokenURL     string
	GoogleAdminBaseURL string
	// PostgresExcludeRoles are extra Postgres roles never reported (Fortik's
	// own database user, YAML upstream users on the same cluster).
	PostgresExcludeRoles []string
	// GitHubKnownApps are app slugs the organisation approved.
	GitHubKnownApps []string
	Log             *slog.Logger
}

// New returns the four discoverers (each is also the revoker of its system).
func New(cfg Config) ([]shadow.Discoverer, error) {
	if cfg.Integrations == nil {
		return nil, errors.New("shadow discoverers: an integrations source is required")
	}
	return []shadow.Discoverer{
		NewPostgres(cfg.Integrations, cfg.PostgresExcludeRoles, cfg.Log),
		NewGitHub(cfg.Integrations, cfg.GitHub, cfg.GitHubKnownApps, cfg.Log),
		NewAWS(cfg.Integrations, cfg.HTTPClient, cfg.Log),
		NewGoogle(cfg.Integrations, cfg.HTTPClient, cfg.GoogleTokenURL, cfg.GoogleAdminBaseURL, cfg.Log),
	}, nil
}

var (
	_ shadow.Revoker = (*Postgres)(nil)
	_ shadow.Revoker = (*GitHub)(nil)
	_ shadow.Revoker = (*AWS)(nil)
	_ shadow.Revoker = (*Google)(nil)
)
