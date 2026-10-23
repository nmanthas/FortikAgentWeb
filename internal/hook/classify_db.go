package hook

// Database clients: detection patterns for refusal. The endpoint a client
// would connect to (flags, connection URLs/conninfo, PG*/MYSQL_* variables
// and the environment hints sent by the hook client) is compared with
// config.HookConfig.ProxyHosts; anything else is direct_db (POL-501), i.e.
// database access that bypasses Fortik's audited proxy.

import (
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"fortik/internal/action"
)

// dbClient describes one client family: options that take a value, which
// carry host/port/URL, the default endpoint and environment variables.
type dbClient struct {
	spec        optSpec
	hostFlags   []string
	portFlags   []string
	urlFlags    []string // values that may be a URL or conninfo
	hostEnv     string
	portEnv     string
	defaultHost string
	defaultPort int
	urlOperand  bool // the first operand may be a URL / conninfo
	libpq       bool // libpq: conninfo/URI values override -h/-p; PGHOSTADDR/PGSERVICE apply
}

var pgClient = dbClient{
	spec:      optSpec{shortArg: "hpdUcfvoLTPFRCnNSjZ", longArg: set("host", "port", "dbname", "username", "command", "file", "set", "variable", "output", "log-file", "table-attr", "pset", "field-separator", "record-separator", "format", "jobs", "schema", "table", "exclude-table", "role", "superuser")},
	hostFlags: []string{"-h", "--host"}, portFlags: []string{"-p", "--port"}, urlFlags: []string{"-d", "--dbname"},
	hostEnv: "PGHOST", portEnv: "PGPORT", defaultHost: "socket:local", defaultPort: 5432, urlOperand: true, libpq: true,
}

var dbClients = map[string]dbClient{
	"psql": pgClient, "pg_dump": pgClient, "pg_dumpall": pgClient, "pg_restore": pgClient, "pgcli": pgClient,
	"mysql": {spec: optSpec{shortArg: "hPuDeSE", shortOpt: "p", longArg: set("host", "port", "user", "database", "execute", "socket")},
		hostFlags: []string{"-h", "--host"}, portFlags: []string{"-P", "--port"}, hostEnv: "MYSQL_HOST", portEnv: "MYSQL_TCP_PORT",
		defaultHost: "127.0.0.1", defaultPort: 3306},
	"mongosh": {spec: optSpec{shortArg: "upf", longArg: set("host", "port", "username", "password", "eval", "file", "authenticationDatabase")},
		hostFlags: []string{"--host"}, portFlags: []string{"--port"}, defaultHost: "127.0.0.1", defaultPort: 27017, urlOperand: true},
	"redis-cli": {spec: optSpec{shortArg: "hpanu", longArg: set("user", "pass")}, hostFlags: []string{"-h"}, portFlags: []string{"-p"},
		urlFlags: []string{"-u"}, defaultHost: "127.0.0.1", defaultPort: 6379},
	"sqlcmd": {spec: optSpec{shortArg: "SUPdQqi"}, hostFlags: []string{"-S"}, defaultHost: "127.0.0.1", defaultPort: 1433},
}

func registerDB() {
	for n, cl := range dbClients {
		register(dbHandler(cl), n)
	}
	for alias, n := range map[string]string{"mariadb": "mysql", "mysqldump": "mysql", "mariadb-dump": "mysql", "mongo": "mongosh", "mongodump": "mongosh", "mongorestore": "mongosh"} {
		register(dbHandler(dbClients[n]), alias)
	}
}

func dbHandler(cl dbClient) handler {
	return func(c *classifier, name string, args []arg, ctx callCtx) flow {
		return c.dbConnect(cl, name, args, ctx)
	}
}

func (c *classifier) dbConnect(cl dbClient, _ string, args []arg, ctx callCtx) flow {
	p := parseOpts(args, cl.spec)
	if len(args) > 0 && len(p.operands()) == 0 && p.has("--version", "-V", "--help", "-?") && len(p.flags) == 1 {
		return flow{} // version/help only: no connection
	}
	c.verb(action.VerbExecute)
	c.op("database")
	host, port, known := "", 0, true
	setHP := func(h string, pt int) {
		if h != "" {
			host = h
		}
		if pt > 0 {
			port = pt
		}
	}
	// Precedence (lowest first): defaults, environment, then flags and
	// URL/conninfo. libpq passes the dbname conninfo with expand_dbname
	// AFTER -h/-p, so its values win there; other clients let flags win.
	if v, ok, k := c.lookupVar(ctx, cl.hostEnv); cl.hostEnv != "" && ok {
		known = known && k
		setHP(v, 0)
	}
	if v, ok, k := c.lookupVar(ctx, cl.portEnv); cl.portEnv != "" && ok {
		known = known && k
		n, _ := strconv.Atoi(v)
		setHP("", n)
	}
	if cl.libpq {
		// A service file can name any host.
		for _, e := range []string{"PGSERVICE", "PGSERVICEFILE"} {
			if _, ok, _ := c.lookupVar(ctx, e); ok {
				known = false
			}
		}
	}
	var conn []arg
	if ops := p.operands(); cl.urlOperand && len(ops) > 0 {
		conn = append(conn, ops[0])
	}
	conn = append(conn, p.vals(cl.urlFlags...)...)
	applyConn := func() {
		for _, a := range conn {
			if !a.lit {
				known = false
				continue
			}
			h, pt, ok := parseConn(a.val)
			known = known && ok
			setHP(h, pt)
		}
	}
	if !cl.libpq {
		applyConn()
	}
	for _, a := range p.vals(cl.hostFlags...) {
		if !a.lit {
			known = false
			continue
		}
		h, pt := splitHostPort(a.val)
		setHP(h, pt)
	}
	for _, a := range p.vals(cl.portFlags...) {
		if !a.lit {
			known = false
			continue
		}
		n, _ := strconv.Atoi(a.val)
		setHP("", n)
	}
	if cl.libpq {
		applyConn()
		// PGHOSTADDR is the address actually dialled, whatever -h or a
		// conninfo host= say (only a conninfo hostaddr= replaces it).
		connAddr := false
		for _, a := range conn {
			connAddr = connAddr || strings.Contains(a.val, "hostaddr")
		}
		if v, ok, k := c.lookupVar(ctx, "PGHOSTADDR"); ok && !connAddr {
			known = known && k
			setHP(v, 0)
		}
	}
	if !known {
		c.dbEndpoint("unknown", false)
		return flow{}
	}
	if host == "" {
		host = cl.defaultHost
	}
	if port == 0 {
		port = cl.defaultPort
	}
	if strings.HasPrefix(host, "/") {
		host = "socket:" + host
	}
	host = strings.Split(host, ",")[0] // multi-host lists: judge the first
	hp := HostPort{Host: canonHost(host), Port: port}
	if strings.HasPrefix(host, "socket:") {
		hp.Host = host
	}
	c.dbEndpoint(hp.String(), isProxy(hp, c.env.ProxyHosts))
	c.extHost(hp.Host)
	return flow{}
}

func (c *classifier) dbEndpoint(hp string, proxied bool) {
	addUnique(&c.res.DBHosts, hp)
	if !proxied {
		c.res.DirectDB = true
		c.op("direct_db")
	}
}

// parseConn reads host/port from a URL (postgres://, mysql://, mongodb://,
// redis://) or a libpq conninfo string ("host=x port=y"). A bare database
// name yields nothing. Like libpq, URI query parameters (host, hostaddr,
// port) override the authority and hostaddr is the address dialled. ok is
// false when the endpoint cannot be known (service=, unparsable URL).
func parseConn(s string) (string, int, bool) {
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return "", 0, false
		}
		q := u.Query()
		if q.Has("service") {
			return "", 0, false
		}
		h := u.Hostname()
		if i := strings.IndexByte(u.Host, ','); i >= 0 { // multi-host
			h, _ = splitHostPort(u.Host[:i])
		}
		pt, _ := strconv.Atoi(u.Port())
		if v := q.Get("host"); v != "" {
			h = v
		}
		if v := q.Get("hostaddr"); v != "" {
			h = v
		}
		if v := q.Get("port"); v != "" {
			pt, _ = strconv.Atoi(strings.Split(v, ",")[0])
		}
		return h, pt, true
	}
	if !strings.Contains(s, "=") {
		return "", 0, true
	}
	var h, addr string
	var pt int
	for _, kv := range strings.Fields(conninfoEq.ReplaceAllString(s, "=")) {
		k, v, _ := strings.Cut(kv, "=")
		v = strings.Trim(v, "'")
		switch strings.TrimSpace(k) {
		case "host":
			h = v
		case "hostaddr":
			addr = v
		case "port":
			pt, _ = strconv.Atoi(strings.Split(v, ",")[0])
		case "service":
			return "", 0, false
		}
	}
	if addr != "" {
		h = addr
	}
	return h, pt, true
}

// conninfoEq: libpq allows blanks around "=" ("host = x").
var conninfoEq = regexp.MustCompile(`\s*=\s*`)

// splitHostPort accepts "host", "host:port", "[v6]:port" and sqlcmd's
// "tcp:host,port".
func splitHostPort(s string) (string, int) {
	s = strings.TrimPrefix(strings.ToLower(s), "tcp:")
	if h, p, ok := strings.Cut(s, ","); ok {
		n, _ := strconv.Atoi(p)
		return h, n
	}
	if h, p, err := net.SplitHostPort(s); err == nil {
		n, _ := strconv.Atoi(p)
		return h, n
	}
	return s, 0
}
