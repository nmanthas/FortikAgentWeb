package hook

// Wrappers, interpreters, eval and source: detection patterns for refusal.
// A wrapper (sudo, env, nohup, xargs ...) runs another command, which is
// classified in its place. Interpreters given a literal script (bash -c
// '...', a quoted here-doc) are parsed recursively (depth-limited); any
// script Fortik cannot see (variables, downloads, decoded input) makes the
// command dynamic (held by POL-506) or pipes_to_shell (POL-502).

import (
	"regexp"
	"strings"

	"fortik/internal/action"
)

// wrapperSpecs: wrappers and the options that take a value (so the wrapped
// command is found after them).
var wrapperSpecs = map[string]optSpec{
	"sudo":       {shortArg: "uUgpChDrtTR", longArg: set("user", "group", "prompt", "close-from", "chdir", "role", "type", "other-user", "host", "chroot"), stopAtPos: true},
	"doas":       {shortArg: "uC", stopAtPos: true},
	"pkexec":     {longArg: set("user"), stopAtPos: true},
	"nohup":      {stopAtPos: true},
	"time":       {shortArg: "fo", longArg: set("format", "output"), stopAtPos: true},
	"nice":       {shortArg: "n", longArg: set("adjustment"), stopAtPos: true},
	"ionice":     {shortArg: "cnp", stopAtPos: true},
	"timeout":    {shortArg: "sk", longArg: set("signal", "kill-after"), stopAtPos: true},
	"command":    {stopAtPos: true},
	"builtin":    {stopAtPos: true},
	"exec":       {shortArg: "a", stopAtPos: true},
	"stdbuf":     {shortArg: "ioe", longArg: set("input", "output", "error"), stopAtPos: true},
	"caffeinate": {shortArg: "tw", stopAtPos: true},
	"chroot":     {longArg: set("userspec", "groups"), stopAtPos: true},
	"setsid":     {stopAtPos: true},
	"unbuffer":   {stopAtPos: true},
	"busybox":    {stopAtPos: true},
	"xargs":      {shortArg: "aEeIiLlnPsd", longArg: set("arg-file", "delimiter", "eof", "replace", "max-lines", "max-args", "max-procs", "max-chars", "process-slot-var"), stopAtPos: true},
}

// privileged wrappers escalate (POL-504).
var privileged = set("sudo", "doas", "pkexec", "su", "runas")

// shells parse a literal -c script; other interpreters only run it.
var shells = set("sh", "bash", "zsh", "dash", "ksh", "mksh", "fish", "ash")

var interpreters = set("python", "python2", "python3", "perl", "ruby", "node", "nodejs", "deno", "bun", "php", "lua", "tclsh", "osascript", "pwsh", "powershell")

func registerWrappers() {
	for n := range wrapperSpecs {
		register(wrapperCmd, n)
	}
	register(suCmd, "su")
	register(envCmd, "env")
	for n := range shells {
		register(interpCmd, n)
	}
	for n := range interpreters {
		register(interpCmd, n)
	}
	register(evalCmd, "eval", "trap", "watch")
	register(sourceCmd, "source", ".")
	register(scriptCmd, "script")
}

// scriptCmd: `script -c CMD [file]` (util-linux) or `script [opts] [file
// [command ...]]` (BSD) runs a command under a pseudo-terminal.
func scriptCmd(c *classifier, _ string, args []arg, ctx callCtx) flow {
	c.verb(action.VerbExecute)
	p := parseOpts(args, optSpec{shortArg: "cEOIBTtF", longArg: set("command", "echo", "log-out", "log-in", "log-io", "log-timing", "logging-format", "output-limit")})
	if v, ok := p.val("-c", "--command"); ok {
		return c.inlineScript(v, ctx)
	}
	ops := p.operands()
	if len(ops) > 0 {
		c.writePath(ops[0], "script")
	}
	if len(ops) > 1 {
		return c.command(ops[1:], ctx)
	}
	return flow{}
}

func wrapperCmd(c *classifier, name string, args []arg, ctx callCtx) flow {
	if privileged[name] {
		c.res.Privilege = true
		c.op("privilege")
		c.verb(action.VerbExecute)
	}
	p := parseOpts(args, wrapperSpecs[name])
	rest := p.operands()
	switch name {
	case "command":
		if p.has("-v", "-V") {
			return flow{}
		}
	case "timeout":
		if len(rest) > 0 {
			rest = rest[1:] // duration
		}
	case "xargs":
		if len(rest) == 0 {
			rest = []arg{litArg("echo")}
		}
		// The wrapped command also receives arguments from stdin.
		rest = append(append([]arg(nil), rest...), arg{})
		ctx = callCtx{vars: ctx.vars}
	}
	if len(rest) == 0 {
		return flow{}
	}
	return c.command(rest, ctx)
}

func suCmd(c *classifier, _ string, args []arg, ctx callCtx) flow {
	c.res.Privilege = true
	c.op("privilege")
	c.verb(action.VerbExecute)
	p := parseOpts(args, optSpec{shortArg: "cs", longArg: set("command", "shell")})
	if v, ok := p.val("-c", "--command"); ok {
		return c.inlineScript(v, ctx)
	}
	return flow{}
}

// envCmd: NAME=VALUE assignments apply to the wrapped command; with no
// command, env prints the environment.
func envCmd(c *classifier, _ string, args []arg, ctx callCtx) flow {
	vars := map[string]arg{}
	for k, v := range ctx.vars {
		vars[k] = v
	}
	i := 0
	for ; i < len(args); i++ {
		a := args[i]
		if !a.lit {
			break
		}
		switch {
		case a.val == "-u" || a.val == "--unset" || a.val == "-C" || a.val == "--chdir" || a.val == "-S":
			if a.val == "-S" && i+1 < len(args) {
				return c.inlineScript(args[i+1], ctx)
			}
			i++
		case a.val == "-i" || a.val == "-" || a.val == "--ignore-environment" || a.val == "-0" || a.val == "--null" || strings.HasPrefix(a.val, "--unset=") || strings.HasPrefix(a.val, "--chdir="):
		case a.val == "--":
			i++
			goto done
		case strings.HasPrefix(a.val, "-"):
		case strings.Contains(a.val, "=") && !strings.HasPrefix(a.val, "="):
			k, v, _ := strings.Cut(a.val, "=")
			vars[k] = litArg(v)
		default:
			goto done
		}
	}
done:
	if i >= len(args) {
		c.res.envDump = true
		return flow{}
	}
	return c.command(args[i:], callCtx{in: ctx.in, vars: vars})
}

// interpCmd: bash/sh/zsh/python... with -c, a script file, or stdin.
func interpCmd(c *classifier, name string, args []arg, ctx callCtx) flow {
	c.verb(action.VerbExecute)
	isShell := shells[name]
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !a.lit {
			// A substituted script: <(curl ...) or "$(...)".
			c.unseenScript(a.flow, "interpreter script is not a literal")
			return flow{}
		}
		switch {
		case a.val == "-c" || (isShell && strings.HasPrefix(a.val, "-") && !strings.HasPrefix(a.val, "--") && strings.Contains(a.val, "c")) ||
			(!isShell && (a.val == "-e" || a.val == "-E" || a.val == "--eval" || a.val == "-p")):
			if i+1 >= len(args) {
				return flow{}
			}
			if !isShell {
				if !args[i+1].lit {
					c.unseenScript(args[i+1].flow, "interpreter code is not a literal")
				} else {
					c.inlineCode(name, args[i+1].val)
				}
				if inPlaceEdit(name, args) {
					sedCmd(c, "perl", args, ctx) // operands are edited in place
				}
				return flow{}
			}
			return c.inlineScript(args[i+1], ctx)
		case isShell && (a.val == "-o" || a.val == "+o" || a.val == "-O" || a.val == "+O" || a.val == "--rcfile" || a.val == "--init-file"):
			i++
		case a.val == "-" || a.val == "-s" || isStdinPath(a.val):
			return c.stdinScript(name, ctx)
		case strings.HasPrefix(a.val, "-"):
			continue
		default:
			// A script file: its contents are not visible here.
			c.readPath(a, name)
			return flow{}
		}
	}
	return c.stdinScript(name, ctx)
}

// stdinScript: the interpreter reads its program from standard input.
func (c *classifier) stdinScript(name string, ctx callCtx) flow {
	switch ctx.in.kind {
	case inScript:
		if shells[name] {
			c.nested(ctx.in.script)
		}
	case inPipe, inDynamic:
		if ctx.in.flow.fetch {
			c.res.PipesToShell = true
			c.op("pipes_to_shell")
		}
		if ctx.in.flow.decode || !ctx.in.flow.fetch {
			c.dyn("interpreter reads a script from a pipe or expansion")
		}
	case inFile:
		// `sh < script.sh`: contents not visible, like a script file.
	}
	return flow{}
}

// inlineScript parses a literal -c script; anything else is unseen.
func (c *classifier) inlineScript(a arg, _ callCtx) flow {
	if !a.lit {
		c.unseenScript(a.flow, "shell -c script is not a literal")
		return flow{}
	}
	c.nested(a.val)
	return flow{}
}

// unseenScript records a script Fortik cannot read: downloaded content is
// pipes_to_shell, everything else dynamic.
func (c *classifier) unseenScript(f flow, reason string) {
	c.verb(action.VerbExecute)
	if f.fetch {
		c.res.PipesToShell = true
		c.op("pipes_to_shell")
	}
	if !f.fetch || f.decode {
		c.dyn(reason)
	}
}

// evalCmd: eval/trap/watch run a string as shell code.
func evalCmd(c *classifier, name string, args []arg, ctx callCtx) flow {
	c.verb(action.VerbExecute)
	if name == "trap" && len(args) > 0 {
		args = args[:1]
	}
	if name == "watch" {
		args = parseOpts(args, optSpec{shortArg: "nd", longArg: set("interval", "differences"), stopAtPos: true}).operands()
	}
	parts := make([]string, 0, len(args))
	for _, a := range args {
		if !a.lit {
			c.unseenScript(a.flow, name+" of a non-literal string")
			return flow{}
		}
		parts = append(parts, a.val)
	}
	if len(parts) > 0 {
		c.nested(strings.Join(parts, " "))
	}
	return flow{}
}

// sourceCmd: a literal path runs a file Fortik cannot see (EXECUTE); a
// non-literal path is dynamic.
func sourceCmd(c *classifier, _ string, args []arg, ctx callCtx) flow {
	c.verb(action.VerbExecute)
	if len(args) == 0 {
		return flow{}
	}
	if !args[0].lit {
		c.unseenScript(args[0].flow, "source of a non-literal path")
		return flow{}
	}
	if isStdinPath(args[0].val) {
		// `curl ... | source /dev/stdin`: the piped input is the script.
		return c.stdinScript("bash", ctx)
	}
	c.readPath(args[0], "source")
	return flow{}
}

// isStdinPath: paths that name the process's standard input.
func isStdinPath(p string) bool {
	switch p {
	case "/dev/stdin", "/dev/fd/0", "/proc/self/fd/0":
		return true
	}
	return false
}

// inPlaceEdit: perl/ruby -i (also bundled, -pi, -i.bak) edit their file
// operands.
func inPlaceEdit(name string, args []arg) bool {
	if name != "perl" && name != "ruby" {
		return false
	}
	for _, a := range args {
		if a.lit && strings.HasPrefix(a.val, "-") && !strings.HasPrefix(a.val, "--") {
			flags := a.val[1:]
			if j := strings.IndexAny(flags, "eE"); j >= 0 {
				flags = flags[:j] // -e takes the code; letters after it are not flags
			}
			if strings.Contains(flags, "i") {
				return true
			}
		}
	}
	return false
}

// inlineRisky: primitives in inline interpreter code that run programs,
// reach the network, decode payloads or delete files. Code using them is
// held as dynamic (its effect cannot be read statically).
var inlineRisky = []string{"subprocess", "os.system", "popen", "exec(", "execv", "eval(", "spawn", "child_process",
	"system(", "`", "socket", "urllib", "requests", "http.client", "httplib", "fetch(", "xmlhttprequest", "net/http",
	"net::http", "lwp", "open-uri", "base64", "b64decode", "__import__", "importlib", "compile(", "rmtree", "unlink",
	"os.remove", "fileutils", "shell_exec", "passthru", "proc_open", "curl", "wget", "file_put_contents", "io.popen",
	"os.execute", "do shell script", "invoke-expression", "invoke-webrequest", "start-process", "deno.run", "bun.spawn"}

// inlineToken splits code into candidate paths and URLs.
var inlineToken = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s'"(),;<>` + "`" + `]+|[~./A-Za-z0-9_@+-][^\s'"(),;<>` + "`" + `]*`)

// inlineCode scans literal code given to a non-shell interpreter (python -c,
// perl -e, node -e ...): URLs (hosts, database endpoints) and sensitive
// paths it mentions are recorded, and risky primitives make it dynamic.
func (c *classifier) inlineCode(name, code string) {
	low := strings.ToLower(code)
	for _, r := range inlineRisky {
		if strings.Contains(low, r) {
			c.dyn(name + " inline code uses " + strings.TrimSuffix(r, "("))
			break
		}
	}
	for _, tok := range inlineToken.FindAllString(code, maxListLen*4) {
		if strings.Contains(tok, "://") {
			scheme := strings.ToLower(tok[:strings.Index(tok, "://")])
			switch {
			case strings.HasPrefix(scheme, "postgres"), strings.HasPrefix(scheme, "mysql"), strings.HasPrefix(scheme, "mariadb"),
				strings.HasPrefix(scheme, "mongodb"), strings.HasPrefix(scheme, "redis"):
				c.op("database")
				h, pt, ok := parseConn(tok)
				if !ok || h == "" {
					c.dbEndpoint("unknown", false)
					continue
				}
				hp := HostPort{Host: canonHost(h), Port: pt}
				c.dbEndpoint(hp.String(), pt != 0 && isProxy(hp, c.env.ProxyHosts))
				c.extHost(hp.Host)
			default:
				if h, ok := urlHost(tok); ok {
					c.op("network")
					c.extHost(h)
					c.dyn(name + " inline code names a URL")
				}
			}
			continue
		}
		a := litArg(tok)
		a.tilde = strings.HasPrefix(tok, "~")
		abs, ok := c.resolve(a)
		pth := abs
		if !ok {
			pth = c.tilde(a)
		}
		switch k := sensitiveKind(pth); k {
		case "":
		case KindCredentials:
			// The code may read or write the file: both are recorded.
			c.sensitiveRead(pth)
			c.sensitiveWrite(pth, k)
			addUnique(&c.res.Paths, pth)
		default:
			c.sensitiveWrite(pth, k)
			addUnique(&c.res.Paths, pth)
		}
	}
}
