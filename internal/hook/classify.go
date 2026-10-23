package hook

// Command dispatch for the shell classifier: detection patterns for refusal.
//
// Fortik never executes the commands it classifies. Each family file
// (classify_*.go) holds declarative tables of command names and flags that
// are RECOGNISED so policy (policies/fortik/rules/shell.rego) can REFUSE or
// hold them before Claude Code runs anything.

import (
	"path"
	"regexp"
	"strings"

	"fortik/internal/action"
)

// callCtx is what one simple command sees besides its arguments.
type callCtx struct {
	in   input          // standard input
	vars map[string]arg // per-command assignments (PGHOST=x psql ...)
}

// handler classifies one command family. args excludes the command name.
type handler func(c *classifier, name string, args []arg, ctx callCtx) flow

// handlers maps a command name (base name, lower case) to its family
// handler. Filled in init() because wrappers recurse into command().
var handlers map[string]handler

func register(h handler, names ...string) {
	for _, n := range names {
		handlers[n] = h
	}
}

func init() {
	handlers = map[string]handler{}
	registerRead()
	registerFS()
	registerWrappers()
	registerGit()
	registerNet()
	registerDB()
	registerCloud()
}

// command classifies one resolved simple command (name + arguments).
func (c *classifier) command(args []arg, ctx callCtx) flow {
	if len(args) == 0 {
		return flow{}
	}
	head := args[0]
	if !head.lit {
		// A variable or substitution as the command name: unknowable.
		c.dyn("command name is not a literal")
		c.verb(action.VerbExecute)
		return flow{}
	}
	name := path.Base(head.val)
	if head.val == "" || name == "." && head.val != "." {
		c.dyn("empty command name")
		c.verb(action.VerbExecute)
		return flow{}
	}
	key := strings.ToLower(name)
	if strings.ContainsAny(key, "{}") {
		// Brace expansion ({psql,}, {rm,-rf,/}) is not modelled: the real
		// command name is unknowable here.
		c.cmdName(key)
		c.dyn("command name uses brace expansion")
		c.verb(action.VerbExecute)
		return flow{}
	}
	key = canonCommand(key)
	c.cmdName(key)
	if h, ok := handlers[key]; ok {
		return h(c, key, args[1:], ctx)
	}
	if strings.HasPrefix(key, "mkfs") {
		return diskTool(c, key, args[1:], ctx)
	}
	// Anything else runs a program Fortik does not model. Known development
	// tools are EXECUTE (Claude Code's own permission flow still applies);
	// any other program is held as dynamic (fail closed: a renamed or
	// wrapped client must not slip past the families above). File operands
	// are checked for credentials either way.
	c.verb(action.VerbExecute)
	if !benignTools[key] {
		c.dyn("command is not modelled by the classifier")
	}
	for _, a := range args[1:] {
		if a.lit && !strings.HasPrefix(a.val, "-") {
			c.readPath(a, key)
		}
	}
	return flow{}
}

// versionSuffix: psql-16, psql16, python3.12, gcc-13, pg_dump_15.
var versionSuffix = regexp.MustCompile(`^([a-z][a-z0-9_+-]*?[a-z+])[-_.]?[0-9][0-9.]*$`)

// canonCommand maps a versioned or suffixed program name to the family it
// belongs to (psql-16 -> psql, python3.12 -> python3/python, tool.exe ->
// tool) when the exact name is not known.
func canonCommand(key string) string {
	if _, ok := handlers[key]; ok || benignTools[key] {
		return key
	}
	k := strings.TrimSuffix(key, ".exe")
	if _, ok := handlers[k]; ok || benignTools[k] {
		return k
	}
	for {
		m := versionSuffix.FindStringSubmatch(k)
		if m == nil {
			return key
		}
		// python3.12: prefer python3 when it is known.
		if i := strings.LastIndexByte(k, '.'); i > 0 {
			if _, ok := handlers[k[:i]]; ok {
				return k[:i]
			}
		}
		k = m[1]
		if _, ok := handlers[k]; ok || benignTools[k] {
			return k
		}
	}
}

// benignTools: unmodelled development tools that run as EXECUTE without a
// hold. Programs that run another command (wrappers, interpreters, remote
// shells, containers) are NOT listed here: they have handlers.
var benignTools = set(
	"go", "gofmt", "goimports", "golangci-lint", "staticcheck", "gopls", "govulncheck", "dlv",
	"npm", "npx", "yarn", "pnpm", "corepack", "tsc", "tsx", "ts-node", "eslint", "prettier", "jest", "vitest",
	"mocha", "webpack", "vite", "esbuild", "rollup", "turbo", "nx", "lerna", "playwright", "storybook", "next",
	"make", "gmake", "cmake", "ninja", "meson", "bazel", "bazelisk", "autoconf", "automake", "pkg-config",
	"cargo", "rustc", "rustup", "rustfmt", "gcc", "g++", "cc", "c++", "clang", "clang++", "clang-format", "ld",
	"ar", "nm", "objdump", "otool", "lipo", "strip", "javac", "java", "mvn", "mvnw", "gradle", "gradlew",
	"kotlinc", "sbt", "dotnet", "swift", "swiftc", "xcodebuild", "xcrun", "pod", "flutter", "dart",
	"pip", "pip3", "pipx", "poetry", "uv", "pipenv", "conda", "pytest", "tox", "nox", "black", "ruff", "mypy",
	"pylint", "flake8", "isort", "pyright", "bundle", "bundler", "rake", "rspec", "gem", "rails", "composer",
	"phpunit", "mix", "elixir", "rebar3", "stack", "cabal", "ghc", "protoc", "buf", "sqlc",
	"brew", "apt", "apt-get", "yum", "dnf", "apk", "port", "asdf", "mise", "pre-commit", "shellcheck", "shfmt",
	"hadolint", "actionlint", "yamllint", "markdownlint", "codespell", "tokei", "cloc", "hyperfine",
	"sqlite3", "nproc", "sw_vers", "arch", "sysctl", "vm_stat", "pbpaste", "openapi-generator", "swag", "mockgen",
	"wire", "templ", "golines", "gotestsum", "sass", "tailwindcss", "postcss", "biome", "deno-lint", "jsonlint",
)

// lookupVar resolves a variable for a command: its own assignment first,
// then script-level assignments, then the environment hints. known is false
// when some assignment is not a literal (value unknowable).
func (c *classifier) lookupVar(ctx callCtx, name string) (val string, set, known bool) {
	if a, ok := ctx.vars[name]; ok {
		return a.val, true, a.lit
	}
	if vs, ok := c.vars[name]; ok && len(vs) > 0 {
		for _, v := range vs {
			if !v.lit {
				return "", true, false
			}
		}
		return vs[len(vs)-1].val, true, true
	}
	if v, ok := c.env.Vars[name]; ok && v != "" {
		return v, true, true
	}
	return "", false, true
}

// cd tracks the working directory for relative paths.
func cdCmd(c *classifier, _ string, args []arg, _ callCtx) flow {
	ops := parseOpts(args, optSpec{})
	o := ops.operands()
	switch {
	case len(o) == 0:
		c.cwd = c.env.Home
	case !o[0].lit || o[0].val == "-":
		c.cwd = ""
	default:
		if abs, ok := cleanAbs(c.tilde(o[0]), c.cwd, c.env.Home); ok {
			c.cwd = abs
		} else {
			c.cwd = ""
		}
	}
	return flow{}
}
