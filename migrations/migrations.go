// Package migrations embeds the versioned SQL migrations. Files are applied
// in lexical order exactly once; never edit an applied migration — add a new one.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
