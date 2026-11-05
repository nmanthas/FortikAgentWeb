// Package migrations embeds the versioned SQL migrations. Files are applied
// in lexical order exactly once; never edit an applied migration — add a new one.
package migrations

import (
	"embed"
	"fmt"
	"regexp"
	"strings"
)

//go:embed *.sql
var FS embed.FS

//go:embed app_grants.sql.tmpl
var appGrants string

var roleName = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// AppGrants returns the least-privilege grants for the application role.
func AppGrants(role string) (string, error) {
	if !roleName.MatchString(role) {
		return "", fmt.Errorf("migrations: invalid role name %q", role)
	}
	return strings.ReplaceAll(appGrants, "{{app}}", role), nil
}
