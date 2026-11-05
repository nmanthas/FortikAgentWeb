package integrations

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
)

var (
	sfAPIVersion = regexp.MustCompile(`^[1-9][0-9]{1,2}\.0$`)
	snowTable    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,79}$`)
	sapClient    = regexp.MustCompile(`^[0-9]{3}$`)
	odataPath    = regexp.MustCompile(`^/sap/opu/odata4?/[A-Za-z0-9_/;=.'~-]{1,300}$`)
)

func optional(check func(string) error) func(any) error {
	return func(v any) error {
		if v.(string) == "" {
			return nil
		}
		return check(v.(string))
	}
}

func checkClientID(s string) error {
	return match(oauthClientID, s, "a client ID of letters, digits and - _ . (at most 200)")
}

func checkScope(s string) error {
	return match(oauthScope, s, "space-separated scope values of letters, digits and _ . : -")
}

// checkMCPURL is an absolute https URL (http only for loopback fakes) with a path.
func checkMCPURL(s string) error {
	if err := checkURL(s); err != nil {
		return err
	}
	if u, _ := url.Parse(s); u.Path == "" || u.Path == "/" {
		return errors.New("must include the MCP server's path")
	}
	return nil
}

func label(s string) error { return checkLabel(s, 200) }

func init() {
	v := configValidators
	for _, sys := range []string{SystemSalesforceMCP, SystemServiceNowMCP, SystemSAPMCP} {
		v[sys+".endpoint_url"] = func(x any) error { return checkMCPURL(x.(string)) }
		v[sys+".client_id"] = optional(checkClientID)
		v[sys+".scope"] = optional(checkScope)
		v[sys+".redirect_uri"] = optional(checkRedirectURI)
	}
	v["salesforce_mcp.instance_url"] = optional(checkURL)
	for _, k := range []string{"authorize_url", "token_url", "revoke_url"} {
		v["sap_mcp."+k] = optional(checkURL)
	}
	v["salesforce.instance_url"] = func(x any) error { return checkURL(x.(string)) }
	v["salesforce.client_id"] = func(x any) error { return checkClientID(x.(string)) }
	v["salesforce.username"] = optional(label)
	v["salesforce.audience"] = optional(checkURL)
	v["salesforce.api_version"] = func(x any) error { return match(sfAPIVersion, x, "a version such as 62.0") }
	v["servicenow.instance_url"] = func(x any) error { return checkURL(x.(string)) }
	v["servicenow.username"] = optional(label)
	v["servicenow.client_id"] = optional(checkClientID)
	v["servicenow.test_tables"] = func(x any) error {
		if len(x.([]string)) > 10 {
			return errors.New("at most 10 tables")
		}
		return eachString(x, func(s string) error { return match(snowTable, s, "table names such as incident") })
	}
	v["sap.api_base_url"] = func(x any) error { return checkURL(x.(string)) }
	v["sap.username"] = optional(label)
	v["sap.token_url"] = optional(checkURL)
	v["sap.client_id"] = optional(checkClientID)
	v["sap.scope"] = optional(checkScope)
	v["sap.sap_client"] = optional(func(s string) error { return match(sapClient, s, "a three-digit client such as 100") })
	v["sap.services"] = func(x any) error {
		list := x.([]string)
		if len(list) == 0 || len(list) > 10 {
			return errors.New("list 1 to 10 OData service paths")
		}
		return eachString(x, func(s string) error {
			return match(odataPath, s, "OData service paths under /sap/opu/odata/ or /sap/opu/odata4/")
		})
	}
	secretValidators["salesforce.private_key_pem"] = checkRSAPrivateKeyPEM
}

// saasCross checks fields required by the selected authentication (secrets
// are checked when the connection is tested: their values are not here).
func saasCross(system string, cfg map[string]any) error {
	str := func(k string) string { s, _ := cfg[k].(string); return strings.TrimSpace(s) }
	need := func(when string, keys ...string) error {
		for _, k := range keys {
			if str(k) == "" {
				return invalid("%s is required with %s", k, when)
			}
		}
		return nil
	}
	switch system {
	case SystemSalesforce:
		if str("auth_flow") == "jwt_bearer" {
			return need("jwt_bearer", "username")
		}
	case SystemServiceNow, SystemSAP:
		switch str("auth_type") {
		case "basic":
			return need("basic", "username")
		case AuthClientCreds:
			if system == SystemSAP {
				return need(AuthClientCreds, "token_url", "client_id")
			}
			return need(AuthClientCreds, "client_id")
		}
	case SystemSalesforceMCP, SystemServiceNowMCP, SystemSAPMCP:
		auth := str("auth_type")
		if auth == AuthOAuthCode || auth == AuthClientCreds {
			if err := need(auth, "client_id"); err != nil {
				return err
			}
		}
		switch {
		case system == SystemSalesforceMCP && auth != AuthBearer:
			return need(auth, "instance_url")
		case system == SystemSAPMCP && auth == AuthOAuthCode:
			return need(auth, "authorize_url", "token_url")
		case system == SystemSAPMCP && auth == AuthClientCreds:
			return need(auth, "token_url")
		}
	}
	return nil
}
