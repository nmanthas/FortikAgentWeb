package hook

// Network egress and remote copy/shell: detection patterns for refusal.
// URLs and hosts are extracted so policy can hold uploads to external hosts
// (POL-505) and refuse downloads piped into a shell (POL-502). Nothing is
// fetched or sent by the classifier.

import (
	"strings"

	"fortik/internal/action"
)

// curlSpec: curl options that take a value.
var curlSpec = optSpec{
	shortArg: "dFTXoHuAeEbcrKmwxyzYtCQUP",
	longArg: set("data", "data-ascii", "data-binary", "data-raw", "data-urlencode", "json", "form", "form-string",
		"upload-file", "request", "output", "header", "user", "user-agent", "referer", "cert", "cookie", "cookie-jar",
		"config", "max-time", "proxy", "url", "connect-timeout", "retry", "resolve", "connect-to", "cacert", "key",
		"output-dir", "write-out", "range", "time-cond", "limit-rate", "interface", "dns-servers", "oauth2-bearer"),
}

// curlUpload: options that send a request body or file.
var curlUpload = []string{"-d", "--data", "--data-ascii", "--data-binary", "--data-raw", "--data-urlencode", "--json", "-F", "--form", "--form-string", "-T", "--upload-file"}

// uploadMethods: HTTP methods that send data.
var uploadMethods = set("POST", "PUT", "PATCH", "DELETE")

var wgetSpec = optSpec{shortArg: "OoaeiPUTtwQ", longArg: set("output-document", "output-file", "post-data", "post-file", "body-data", "body-file", "method", "header", "user", "password", "user-agent", "directory-prefix", "tries", "timeout")}

func registerNet() {
	register(curlCmd, "curl")
	register(wgetCmd, "wget")
	register(httpieCmd, "http", "https", "xh", "xhs")
	register(ncCmd, "nc", "ncat", "netcat", "socat", "telnet")
	register(scpCmd, "scp", "rsync", "sftp")
	register(sshCmd, "ssh")
	register(opensslCmd, "openssl")
	register(archiveCmd, "tar", "bsdtar", "gtar", "unzip", "zip", "7z", "7za")
}

// opensslCmd: s_client opens a raw TLS connection that sends whatever is on
// stdin; `enc -d` / `base64 -d` decode; anything else only reads files.
func opensslCmd(c *classifier, name string, args []arg, ctx callCtx) flow {
	c.verb(action.VerbExecute)
	if len(args) == 0 || !args[0].lit {
		return flow{}
	}
	switch strings.ToLower(args[0].val) {
	case "s_client":
		c.op("network")
		var urls []arg
		for i := 1; i < len(args); i++ {
			if args[i].lit && (args[i].val == "-connect" || args[i].val == "-host") && i+1 < len(args) {
				if !args[i+1].lit {
					urls = append(urls, args[i+1])
				} else {
					urls = append(urls, litArg("tls://"+args[i+1].val))
				}
				i++
			}
		}
		if len(urls) == 0 {
			urls = []arg{litArg("tls://127.0.0.1:4433")}
		}
		return c.egress(urls, ctx.in.kind == inPipe || ctx.in.kind == inFile, false)
	case "enc", "base64":
		if hasLit(args, "-d") {
			return flow{decode: true}
		}
	}
	for i := 1; i < len(args); i++ {
		a := args[i]
		if !a.lit {
			continue
		}
		if a.val == "-out" && i+1 < len(args) {
			c.writePath(args[i+1], name)
			i++
			continue
		}
		if !strings.HasPrefix(a.val, "-") {
			c.readPath(a, name)
		}
	}
	return flow{}
}

// archiveCmd: extraction writes into the destination directory (tar -C /
// --directory, unzip -d, 7z -o), or the current directory; creation writes
// the archive and reads its members.
func archiveCmd(c *classifier, name string, args []arg, _ callCtx) flow {
	c.verb(action.VerbWrite)
	var dests, files, ops []arg
	extract := false
	switch name {
	case "unzip":
		extract = !hasLit(args, "-l", "-t", "-v", "-Z", "-p")
		p := parseOpts(args, optSpec{shortArg: "dxP"})
		dests = p.vals("-d")
	case "zip":
		p := parseOpts(args, optSpec{shortArg: "bnPtx", longArg: set("password")})
		if o := p.operands(); len(o) > 0 {
			files = o[:1]
			ops = o[1:]
		}
	case "7z", "7za":
		if len(args) > 0 && args[0].lit && (args[0].val == "x" || args[0].val == "e") {
			extract = true
		}
		for _, a := range args {
			if a.lit && strings.HasPrefix(a.val, "-o") && len(a.val) > 2 {
				dests = append(dests, litArg(a.val[2:]))
			}
		}
	default: // tar
		p := parseOpts(args, optSpec{shortArg: "fCbTXIL", longArg: set("file", "directory", "files-from", "exclude-from", "exclude", "use-compress-program", "transform", "owner", "group", "mode", "format", "blocking-factor")})
		for _, a := range args {
			if a.lit && (a.val == "--extract" || a.val == "--get" || (!strings.HasPrefix(a.val, "--") && strings.Contains(strings.TrimPrefix(a.val, "-"), "x") && (strings.HasPrefix(a.val, "-") || a == args[0]))) {
				extract = true
			}
		}
		dests = p.vals("-C", "--directory")
		if len(args) > 0 && args[0].lit && !strings.HasPrefix(args[0].val, "-") && strings.Contains(args[0].val, "C") {
			// Old-style bundled options: values follow in order, not handled; be conservative.
			c.dyn("tar old-style options with C")
		}
		f := p.vals("-f", "--file")
		if extract {
			for _, a := range f {
				c.readPath(a, name)
			}
		} else {
			files = f
			ops = p.operands()
			if len(args) > 0 && args[0].lit && !strings.HasPrefix(args[0].val, "-") && len(ops) > 0 {
				ops = ops[1:] // the bundled option word
			}
		}
	}
	if extract {
		if len(dests) == 0 {
			dests = []arg{litArg(".")}
		}
		for _, d := range dests {
			c.writePath(d, name)
		}
		return flow{}
	}
	for _, f := range files {
		if !(f.lit && f.val == "-") {
			c.writePath(f, name)
		}
	}
	for _, o := range ops {
		c.readPath(o, name)
	}
	return flow{}
}

func curlCmd(c *classifier, _ string, args []arg, ctx callCtx) flow {
	c.op("network")
	p := parseOpts(args, curlSpec)
	urls := append(p.vals("--url"), p.operands()...)
	upload := p.has(curlUpload...)
	if m, ok := p.val("-X", "--request"); ok && m.lit && uploadMethods[strings.ToUpper(m.val)] {
		upload = true
	}
	for _, v := range p.vals(curlUpload...) {
		if v.lit && strings.HasPrefix(v.val, "@") && v.val != "@-" {
			if c.readPath(litArg(strings.TrimPrefix(v.val, "@")), "curl") {
				c.res.uploadFiles = true
			}
		} else if v.lit && strings.Contains(v.val, "=@") {
			_, f, _ := strings.Cut(v.val, "=@")
			if c.readPath(litArg(strings.Split(f, ";")[0]), "curl") {
				c.res.uploadFiles = true
			}
		}
	}
	// --data-urlencode name@file / @file sends the file's contents (a "="
	// before the "@" makes it literal content instead).
	for _, v := range p.vals("--data-urlencode") {
		if !v.lit {
			continue
		}
		eq, at := strings.IndexByte(v.val, '='), strings.IndexByte(v.val, '@')
		if at > 0 && (eq < 0 || at < eq) && v.val[at+1:] != "-" {
			if c.readPath(litArg(v.val[at+1:]), "curl") {
				c.res.uploadFiles = true
			}
		}
	}
	// -K/--config reads options (URLs, data, headers) from a file: the file
	// is read, and what it makes curl do is not visible here.
	for _, k := range p.vals("-K", "--config") {
		if c.readPath(k, "curl") {
			c.res.uploadFiles = true
			upload = true
		}
		c.dyn("curl reads options from a config file")
	}
	for _, t := range p.vals("-T", "--upload-file") {
		if c.readPath(t, "curl") {
			c.res.uploadFiles = true
		}
	}
	out := p.has("-o", "--output", "-O", "--remote-name", "--remote-name-all")
	for _, o := range p.vals("-o", "--output") {
		if !(o.lit && o.val == "-") {
			c.writePath(o, "curl")
		} else {
			out = false
		}
	}
	return c.egress(urls, upload, out)
}

// egress records the hosts of urls and the verb; it returns a fetch flow
// when the response goes to standard output.
func (c *classifier) egress(urls []arg, upload, toFile bool) flow {
	external := false
	for _, u := range urls {
		if !u.lit {
			c.dyn("URL is not a literal")
			external = true
			continue
		}
		if h, ok := urlHost(u.val); ok {
			c.extHost(h)
			if isExternal(h, c.env.InternalHosts) {
				external = true
			}
		}
	}
	switch {
	case upload && external:
		c.res.Uploads = true
		c.op("upload")
		c.verb(action.VerbExport)
	case upload:
		c.res.Uploads = true
		c.op("upload")
		c.verb(action.VerbSend)
	}
	if toFile {
		return flow{}
	}
	return flow{fetch: true}
}

func wgetCmd(c *classifier, _ string, args []arg, _ callCtx) flow {
	c.op("network")
	p := parseOpts(args, wgetSpec)
	upload := p.has("--post-data", "--post-file", "--body-data", "--body-file")
	if m, ok := p.val("--method"); ok && m.lit && uploadMethods[strings.ToUpper(m.val)] {
		upload = true
	}
	for _, f := range p.vals("--post-file", "--body-file") {
		if c.readPath(f, "wget") {
			c.res.uploadFiles = true
		}
	}
	toFile := true
	if o, ok := p.val("-O", "--output-document"); ok {
		if o.lit && o.val == "-" {
			toFile = false
		} else {
			c.writePath(o, "wget")
		}
	} else {
		c.verb(action.VerbWrite) // saves into the current directory
	}
	return c.egress(p.operands(), upload, toFile)
}

// httpieCmd: [METHOD] URL [items]; data items (k=v, k:=json, k@file) or a
// sending method make it an upload.
func httpieCmd(c *classifier, _ string, args []arg, ctx callCtx) flow {
	c.op("network")
	p := parseOpts(args, optSpec{shortArg: "aAo", longArg: set("auth", "auth-type", "output", "session", "verify", "cert", "proxy", "timeout")})
	ops := p.operands()
	upload := p.has("-f", "--form", "--raw") || ctx.in.kind == inPipe || ctx.in.kind == inFile
	if len(ops) > 0 && ops[0].lit && uploadMethods[strings.ToUpper(ops[0].val)] {
		upload = true
		ops = ops[1:]
	} else if len(ops) > 0 && ops[0].lit && strings.ToUpper(ops[0].val) == ops[0].val && !strings.ContainsAny(ops[0].val, "./:") {
		ops = ops[1:]
	}
	if len(ops) == 0 {
		return flow{}
	}
	for _, it := range ops[1:] {
		if it.lit && (strings.Contains(it.val, "=") || strings.Contains(it.val, "@")) && !strings.Contains(it.val, "==") {
			upload = true
			if _, f, ok := strings.Cut(it.val, "@"); ok && c.readPath(litArg(f), "http") {
				c.res.uploadFiles = true
			}
		}
	}
	return c.egress(ops[:1], upload, p.has("-o", "--output", "-d", "--download"))
}

// ncCmd: raw sockets send whatever is on stdin.
func ncCmd(c *classifier, _ string, args []arg, ctx callCtx) flow {
	c.op("network")
	c.verb(action.VerbExecute)
	p := parseOpts(args, optSpec{shortArg: "pswiqOIVXxTe"})
	var urls []arg
	for _, o := range p.operands() {
		if o.lit && !isDigits(o.val) {
			urls = append(urls, o)
		}
	}
	return c.egress(urls, ctx.in.kind == inPipe || ctx.in.kind == inFile, false)
}

// scpCmd: an operand naming a host ([user@]host:path, rsync://) is remote;
// the last operand is the destination (remote = upload).
func scpCmd(c *classifier, name string, args []arg, _ callCtx) flow {
	c.op("network")
	c.verb(action.VerbWrite)
	p := parseOpts(args, optSpec{shortArg: "cFiJloPSe", longArg: set("rsh", "rsync-path", "exclude", "include", "filter", "password-file", "port", "chmod", "chown", "files-from", "exclude-from", "include-from", "log-file", "backup-dir", "temp-dir", "partial-dir", "compare-dest", "link-dest")})
	ops := p.operands()
	if name == "sftp" && len(ops) > 0 {
		ops = []arg{litArg(ops[0].val + ":")}
	}
	remote := false
	for i, o := range ops {
		if !o.lit {
			continue
		}
		h, ok := remoteSpec(o.val)
		if !ok {
			if i == len(ops)-1 {
				c.writePath(o, name)
			} else if c.readPath(o, name) {
				c.res.uploadFiles = true
			}
			continue
		}
		remote = true
		c.extHost(h)
		if i == len(ops)-1 && len(ops) > 1 {
			c.res.Uploads = true
			c.verb(action.VerbExport)
		}
	}
	if remote || name == "sftp" {
		c.op("remote_copy")
	}
	if p.hasPrefix("--delete") || p.has("--remove-source-files") {
		c.destructive(name+" --delete", "filesystem", ScopeUnknown, "")
	}
	return flow{}
}

var sshSpec = optSpec{shortArg: "bcDEeFIiJLlmOopQRSWw", stopAtPos: true}

func sshCmd(c *classifier, _ string, args []arg, ctx callCtx) flow {
	c.op("network")
	c.verb(action.VerbExecute)
	p := parseOpts(args, sshSpec)
	rest := p.operands()
	if len(rest) == 0 {
		return flow{}
	}
	if rest[0].lit {
		if h, ok := sshDestination(rest[0].val); ok {
			c.extHost(h)
		}
	} else {
		c.dyn("ssh destination is not a literal")
	}
	c.op("remote_shell")
	if ctx.in.kind == inPipe || ctx.in.kind == inFile {
		c.res.Uploads = true
	}
	// The remote command is shell code too: classify it (a database client
	// or destructive command run through ssh is still one).
	if len(rest) > 1 {
		parts := make([]string, 0, len(rest)-1)
		for _, a := range rest[1:] {
			if !a.lit {
				c.dyn("ssh remote command is not a literal")
				return flow{fetch: true}
			}
			parts = append(parts, a.val)
		}
		c.nested(strings.Join(parts, " "))
	}
	return flow{fetch: true}
}
