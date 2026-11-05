package nsquickstart

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"fortik/internal/action"
	"fortik/internal/integrations"
)

// MappingFile is the QuickStart tool mapping, relative to the policy
// directory (rego reads it as data.fortik.netsuite_quickstart);
// MappingFileAIConnector is a full account's AI Connector Service mapping.
const (
	MappingFile            = "fortik/netsuite_quickstart/data.json"
	MappingFileAIConnector = "fortik/netsuite_mcp/data.json"
)

// LoadMappings reads the tool mapping of every NetSuite MCP connection type.
func LoadMappings(policyDir string) (map[string]*Mapping, error) {
	out := map[string]*Mapping{}
	for _, system := range MCPSystems {
		file := kinds[system].mappingFile
		raw, err := os.ReadFile(filepath.Join(policyDir, filepath.FromSlash(file)))
		if err != nil {
			return nil, fmt.Errorf("mcp: read tool mapping %s: %w", file, err)
		}
		// Only QuickStart ships a mapping; the others start empty (every
		// tool refused until mapped from a real server's tools/list).
		m, err := parseMapping(raw, system != integrations.SystemNetSuiteQuickStart)
		if err != nil {
			return nil, err
		}
		out[system] = m
	}
	return out, nil
}

// ToolClass is how one QuickStart tool is expressed in Fortik's model.
type ToolClass struct {
	Verb      action.Verb `json:"verb"`
	Operation string      `json:"operation"`
}

// Mapping is the explicit tool table. A tool missing from it is UNKNOWN
// (policy denies it) whatever its name or annotations suggest.
type Mapping struct {
	Version string               `json:"mapping_version"`
	Tools   map[string]ToolClass `json:"tools"`
}

// LoadMapping reads the mapping from the policy directory.
func LoadMapping(policyDir string) (*Mapping, error) {
	raw, err := os.ReadFile(filepath.Join(policyDir, filepath.FromSlash(MappingFile)))
	if err != nil {
		return nil, fmt.Errorf("netsuite quickstart: read tool mapping: %w", err)
	}
	return ParseMapping(raw)
}

// ParseMapping parses and checks the mapping: every entry needs a known verb
// and an operation.
func ParseMapping(raw []byte) (*Mapping, error) { return parseMapping(raw, false) }

// parseMapping parses a mapping; allowEmpty accepts a mapping without tools
// (every tool is then refused).
func parseMapping(raw []byte, allowEmpty bool) (*Mapping, error) {
	var f struct {
		Mapping
		PaymentPatterns []string `json:"payment_transform_patterns"`
		Protected       []string `json:"protected_preferences"`
		HighImpact      []string `json:"high_impact_actions"`
		MoneyTypes      []string `json:"money_record_types"`
		Evidence        string   `json:"_evidence"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("netsuite quickstart: parse tool mapping: %w", err)
	}
	if f.Version == "" || f.Tools == nil || len(f.Tools) == 0 && !allowEmpty {
		return nil, errors.New("netsuite quickstart: tool mapping needs mapping_version and tools")
	}
	for name, c := range f.Tools {
		if !action.KnownVerb(c.Verb) || c.Operation == "" {
			return nil, fmt.Errorf("netsuite quickstart: tool mapping entry %q needs a known verb and an operation", name)
		}
	}
	m := f.Mapping
	return &m, nil
}
