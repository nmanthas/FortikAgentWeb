package hook

import (
	"crypto/sha256"
	"encoding/hex"
	"path"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"mvdan.cc/sh/v3/syntax"

	"fortik/internal/action"
)

// ShellClassifier is the version tag every classified shell target carries
// (target.classifier); policy holds shell actions without it (POL-005).
const ShellClassifier = "fortik-shell/1"

// Limits that keep classification bounded on hostile input. Exceeding one
// makes the command dynamic (held), never silently allowed.
const (
	MaxCommandBytes = 64 << 10
	maxNestedParse  = 4   // bash -c "bash -c '...'" levels
	maxSimpleCmds   = 512 // simple commands visited
	maxListLen      = 64  // entries per target list
	maxStringLen    = 256 // bytes per target string
)

// ShellEnv is what the classifier knows about where a command runs.
type ShellEnv struct {
	Cwd           string            // absolute working directory ("" = unknown)
	ProjectDir    string            // project root (defaults to Cwd)
	Home          string            // user's home directory ("" = unknown)
	Vars          map[string]string // environment hints (PGHOST, PGPORT, MYSQL_HOST...)
	ProxyHosts    []HostPort        // database endpoints that ARE the Fortik proxy
	InternalHosts []string          // hosts inside the company
}

// GitOp is one git push found in a command.
type GitOp struct {
	Operation string `json:"operation"` // push | force_push | delete_branch
	Remote    string `json:"remote,omitempty"`
	Branch    string `json:"branch"` // "" = the current branch (unknown); "*" = all branches
}

// GHOp is one GitHub CLI operation.
type GHOp struct {
	Operation string `json:"operation"` // merge_pr, delete_repo, set_secret, run_workflow, ...
	Repo      string `json:"repo,omitempty"`
}

// Destructive is one command that destroys data or infrastructure.
type Destructive struct {
	Command string `json:"command"`
	Kind    string `json:"kind"`  // filesystem | git | disk | infra | power
	Scope   string `json:"scope"` // see Scope* constants
	Path    string `json:"path,omitempty"`
}

// ShellResult is the classification of one shell command line.
type ShellResult struct {
	Verb            action.Verb
	Commands        []string
	Operations      []string
	ExternalHosts   []string
	Uploads         bool
	UploadSensitive bool
	PipesToShell    bool
	DirectDB        bool
	DBHosts         []string
	Dynamic         bool
	DynamicReasons  []string
	Privilege       bool
	Git             []GitOp
	AWSActions      []string
	GH              []GHOp
	Destructive     []Destructive
	Paths           []string
	SensitiveWrites []string
	SensitiveKinds  []string // kinds of SensitiveWrites (see Kind* constants)
	SensitiveReads  []string
	Fingerprint     string

	envDump     bool // env/printenv output (secrets in the environment)
	uploadFiles bool // an upload's source is a credential file
}

var verbRank = map[action.Verb]int{
	action.VerbRead: 0, action.VerbWrite: 1, action.VerbExecute: 2, action.VerbSend: 3,
	action.VerbExport: 4, action.VerbDelete: 5, action.VerbGrant: 6,
}

// Target is the action target for system "shell" (docs/POLICIES.md adapter
// contract). It never contains the command text: only command names,
// hosts, paths and flags (a command line can carry passwords and tokens).
func (r ShellResult) Target(cwd string) map[string]any {
	t := map[string]any{
		"classifier":       ShellClassifier,
		"fingerprint":      r.Fingerprint,
		"commands":         nonNilStrings(r.Commands),
		"operations":       nonNilStrings(r.Operations),
		"external_hosts":   nonNilStrings(r.ExternalHosts),
		"external":         len(r.ExternalHosts) > 0,
		"uploads":          r.Uploads,
		"upload_sensitive": r.UploadSensitive,
		"pipes_to_shell":   r.PipesToShell,
		"direct_db":        r.DirectDB,
		"db_host":          first(r.DBHosts),
		"db_hosts":         nonNilStrings(r.DBHosts),
		"dynamic":          r.Dynamic,
		"dynamic_reasons":  nonNilStrings(r.DynamicReasons),
		"privilege":        r.Privilege,
		"aws_actions":      nonNilStrings(r.AWSActions),
		"paths":            nonNilStrings(r.Paths),
		"sensitive_writes": nonNilStrings(r.SensitiveWrites),
		"sensitive_kinds":  nonNilStrings(r.SensitiveKinds),
		"sensitive_reads":  nonNilStrings(r.SensitiveReads),
	}
	git := make([]any, 0, len(r.Git))
	for _, g := range r.Git {
		git = append(git, map[string]any{"operation": g.Operation, "op": g.Operation, "remote": g.Remote, "branch": g.Branch,
			"force": g.Operation == "force_push"})
	}
	t["git"] = git
	sp := append(append([]string{}, r.SensitiveWrites...), r.SensitiveReads...)
	t["sensitive_paths"] = sp
	gh := make([]any, 0, len(r.GH))
	for _, g := range r.GH {
		gh = append(gh, map[string]any{"operation": g.Operation, "repo": g.Repo})
	}
	t["gh"] = gh
	d := make([]any, 0, len(r.Destructive))
	for _, x := range r.Destructive {
		d = append(d, map[string]any{"command": x.Command, "kind": x.Kind, "scope": x.Scope, "path": x.Path})
	}
	t["destructive"] = d
	if cwd != "" {
		t["cwd"] = clip(cwd)
	}
	return t
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func first(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

// ClassifyShell parses a command line and classifies every simple command
// in it (pipelines, lists, subshells, substitutions, here-docs, functions,
// nested `bash -c` strings). Anything it cannot resolve is reported as
// dynamic; it never fails open.
func ClassifyShell(cmd string, env ShellEnv) ShellResult {
	sum := sha256.Sum256([]byte(cmd))
	if env.ProjectDir == "" {
		env.ProjectDir = env.Cwd
	}
	c := &classifier{
		env:  env,
		cwd:  cleanDir(env.Cwd),
		vars: map[string][]arg{},
		res:  &ShellResult{Verb: action.VerbRead, Fingerprint: hex.EncodeToString(sum[:16])},
	}
	c.env.ProjectDir = cleanDir(env.ProjectDir)
	c.env.Home = cleanDir(env.Home)
	if len(cmd) > MaxCommandBytes {
		c.dyn("command longer than " + strconv.Itoa(MaxCommandBytes) + " bytes")
		c.verb(action.VerbExecute)
		return c.finish()
	}
	if !utf8.ValidString(cmd) || strings.ContainsRune(cmd, 0) {
		c.dyn("command is not valid UTF-8 text")
		c.verb(action.VerbExecute)
		return c.finish()
	}
	c.script(cmd)
	return c.finish()
}

func cleanDir(d string) string {
	if d == "" || !strings.HasPrefix(d, "/") {
		return ""
	}
	return path.Clean(d)
}

type classifier struct {
	env   ShellEnv
	cwd   string           // current directory as `cd` moves it ("" = unknown)
	vars  map[string][]arg // script-level assignments seen (every value: conservative)
	res   *ShellResult
	depth int // nested parse depth
	steps int // simple commands visited
}

// flow says what a command (or the substitutions in a word) does with data,
// for the "fetched or decoded content reaches a shell" check.
type flow struct {
	fetch  bool // network download (curl, wget, nc ...)
	decode bool // de-obfuscation (base64 -d, xxd -r, gunzip ...)
}

func (f flow) or(g flow) flow { return flow{fetch: f.fetch || g.fetch, decode: f.decode || g.decode} }
func (f flow) any() bool      { return f.fetch || f.decode }

// Kinds of standard input a command receives.
const (
	inNone    = iota
	inPipe    // previous pipeline stage
	inFile    // < file
	inScript  // literal here-doc or here-string
	inDynamic // here-doc/here-string with expansions, < <(...)
)

type input struct {
	kind   int
	script string
	flow   flow
}

func (c *classifier) script(src string) {
	p := syntax.NewParser(syntax.Variant(syntax.LangBash))
	f, err := p.Parse(strings.NewReader(src), "")
	if err != nil {
		c.dyn("command could not be parsed as bash")
		c.verb(action.VerbExecute)
		return
	}
	c.stmts(f.Stmts)
}

// nested parses a literal script handed to an interpreter (bash -c '...',
// here-doc into sh, eval).
func (c *classifier) nested(src string) {
	if c.depth >= maxNestedParse {
		c.dyn("shell nested more than " + strconv.Itoa(maxNestedParse) + " levels")
		c.verb(action.VerbExecute)
		return
	}
	c.depth++
	saved := c.cwd
	c.script(src)
	c.cwd = saved
	c.depth--
}

func (c *classifier) stmts(ss []*syntax.Stmt) flow {
	var f flow
	for _, s := range ss {
		f = f.or(c.stmt(s, input{}))
	}
	return f
}

func (c *classifier) stmt(s *syntax.Stmt, in input) flow {
	if s == nil {
		return flow{}
	}
	in, f := c.redirects(s.Redirs, in)
	if s.Cmd == nil {
		return f
	}
	switch x := s.Cmd.(type) {
	case *syntax.CallExpr:
		f = f.or(c.call(x, in))
	case *syntax.BinaryCmd:
		if x.Op == syntax.Pipe || x.Op == syntax.PipeAll {
			stages := flattenPipe(x)
			var up flow
			for i, st := range stages {
				sin := input{}
				if i > 0 {
					sin = input{kind: inPipe, flow: up}
				} else {
					sin = in
				}
				up = up.or(c.stmt(st, sin))
			}
			f = f.or(up)
		} else {
			f = f.or(c.stmt(x.X, in)).or(c.stmt(x.Y, in))
		}
	case *syntax.Subshell:
		saved := c.cwd
		f = f.or(c.stmtsIn(x.Stmts, in))
		c.cwd = saved
	case *syntax.Block:
		f = f.or(c.stmtsIn(x.Stmts, in))
	case *syntax.IfClause:
		for cl := x; cl != nil; cl = cl.Else {
			f = f.or(c.stmts(cl.Cond)).or(c.stmtsIn(cl.Then, in))
		}
	case *syntax.WhileClause:
		f = f.or(c.stmts(x.Cond)).or(c.stmtsIn(x.Do, in))
	case *syntax.ForClause:
		if wi, ok := x.Loop.(*syntax.WordIter); ok {
			for _, w := range wi.Items {
				f = f.or(c.word(w).flow)
			}
			if wi.Name != nil {
				// The loop variable takes values we track only as "dynamic".
				c.vars[wi.Name.Value] = append(c.vars[wi.Name.Value], arg{})
			}
		} else {
			f = f.or(c.substitutions(x.Loop))
		}
		f = f.or(c.stmtsIn(x.Do, in))
	case *syntax.CaseClause:
		f = f.or(c.word(x.Word).flow)
		for _, it := range x.Items {
			for _, p := range it.Patterns {
				f = f.or(c.word(p).flow)
			}
			f = f.or(c.stmtsIn(it.Stmts, in))
		}
	case *syntax.FuncDecl:
		// The body runs whenever the function is called: classify it as if it ran.
		f = f.or(c.stmt(x.Body, input{}))
	case *syntax.DeclClause:
		f = f.or(c.decl(x))
	case *syntax.TimeClause:
		f = f.or(c.stmt(x.Stmt, in))
	case *syntax.CoprocClause:
		f = f.or(c.stmt(x.Stmt, in))
	case *syntax.ArithmCmd, *syntax.TestClause, *syntax.LetClause:
		f = f.or(c.substitutions(x))
	default:
		c.dyn("unsupported shell construct")
		c.verb(action.VerbExecute)
	}
	return f
}

// stmtsIn runs a statement list where the first statement may receive the
// compound command's stdin (e.g. `curl x | { sh; }`).
func (c *classifier) stmtsIn(ss []*syntax.Stmt, in input) flow {
	var f flow
	for i, s := range ss {
		if i == 0 {
			f = f.or(c.stmt(s, in))
		} else {
			f = f.or(c.stmt(s, input{}))
		}
	}
	return f
}

func flattenPipe(b *syntax.BinaryCmd) []*syntax.Stmt {
	var out []*syntax.Stmt
	var walk func(s *syntax.Stmt)
	walk = func(s *syntax.Stmt) {
		if bc, ok := s.Cmd.(*syntax.BinaryCmd); ok && (bc.Op == syntax.Pipe || bc.Op == syntax.PipeAll) && len(s.Redirs) == 0 {
			walk(bc.X)
			walk(bc.Y)
			return
		}
		out = append(out, s)
	}
	walk(b.X)
	walk(b.Y)
	return out
}

// substitutions classifies every $(...) / <(...) inside an arbitrary node
// (arithmetic, [[ ]] tests, C-style loops) and returns their flow.
func (c *classifier) substitutions(n syntax.Node) flow {
	var f flow
	syntax.Walk(n, func(x syntax.Node) bool {
		switch s := x.(type) {
		case *syntax.CmdSubst:
			f = f.or(c.stmts(s.Stmts))
			return false
		case *syntax.ProcSubst:
			f = f.or(c.stmts(s.Stmts))
			return false
		}
		return true
	})
	return f
}

// decl handles export/declare/local/readonly/typeset: assignments update
// the tracked variables (PGHOST=... for later psql), values may hide
// substitutions.
func (c *classifier) decl(d *syntax.DeclClause) flow {
	var f flow
	for _, a := range d.Args {
		f = f.or(c.assign(a, nil))
	}
	return f
}

// assign records one assignment. call != nil collects per-command
// assignments (`PGHOST=x psql`); otherwise it is a script-level variable.
func (c *classifier) assign(a *syntax.Assign, call map[string]arg) flow {
	var f flow
	if a.Array != nil || a.Index != nil {
		f = f.or(c.substitutions(a))
	}
	var v arg
	if a.Value != nil {
		v = c.word(a.Value)
		f = f.or(v.flow)
	} else {
		v = arg{lit: true}
	}
	if a.Name == nil {
		if a.Value != nil && !v.lit {
			// `export $X` (naked): could set anything.
			c.dyn("assignment name is not a literal")
		}
		return f
	}
	name := a.Name.Value
	if a.Append || a.Array != nil || a.Index != nil {
		v = arg{flow: v.flow}
	}
	if call != nil {
		call[name] = v
	} else if !a.Naked {
		c.vars[name] = append(c.vars[name], v)
	}
	return f
}

// redirects records file writes/reads made by redirections and returns the
// stdin the command will see.
func (c *classifier) redirects(rs []*syntax.Redirect, in input) (input, flow) {
	var f flow
	for _, r := range rs {
		switch r.Op {
		case syntax.Hdoc, syntax.DashHdoc:
			if r.Hdoc == nil {
				in = input{kind: inScript}
				continue
			}
			w := c.word(r.Hdoc)
			f = f.or(w.flow)
			if w.lit {
				in = input{kind: inScript, script: w.val}
			} else {
				in = input{kind: inDynamic, flow: w.flow}
			}
		case syntax.WordHdoc:
			w := c.word(r.Word)
			f = f.or(w.flow)
			if w.lit {
				in = input{kind: inScript, script: w.val}
			} else {
				in = input{kind: inDynamic, flow: w.flow}
			}
		case syntax.RdrIn:
			w := c.word(r.Word)
			f = f.or(w.flow)
			if w.lit {
				c.readPath(w, "redirect")
				in = input{kind: inFile}
			} else {
				in = input{kind: inDynamic, flow: w.flow}
			}
		case syntax.DplIn:
			w := c.word(r.Word)
			f = f.or(w.flow)
		case syntax.RdrOut, syntax.AppOut, syntax.RdrAll, syntax.AppAll, syntax.RdrClob, syntax.AppClob,
			syntax.RdrAllClob, syntax.AppAllClob, syntax.RdrInOut:
			w := c.word(r.Word)
			f = f.or(w.flow)
			c.redirectWrite(w)
		case syntax.DplOut:
			w := c.word(r.Word)
			f = f.or(w.flow)
			if w.lit && (w.val == "-" || isDigits(w.val)) {
				continue // fd duplication (2>&1, >&-)
			}
			c.redirectWrite(w)
		default:
			c.dyn("unsupported redirection")
		}
	}
	return in, f
}

func (c *classifier) redirectWrite(w arg) {
	if !w.lit || w.glob {
		c.dyn("redirect target is not a literal path")
		c.verb(action.VerbWrite)
		return
	}
	abs, ok := cleanAbs(c.tilde(w), c.cwd, c.env.Home)
	if ok && harmlessDevice(abs) {
		return
	}
	c.op("redirect_write")
	c.writePath(w, ">")
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// call classifies one simple command.
func (c *classifier) call(x *syntax.CallExpr, in input) flow {
	c.steps++
	if c.steps > maxSimpleCmds {
		if c.steps == maxSimpleCmds+1 {
			c.dyn("more than " + strconv.Itoa(maxSimpleCmds) + " commands")
			c.verb(action.VerbExecute)
		}
		return flow{}
	}
	var f flow
	if len(x.Args) == 0 {
		for _, a := range x.Assigns {
			f = f.or(c.assign(a, nil))
		}
		return f
	}
	callVars := map[string]arg{}
	for _, a := range x.Assigns {
		f = f.or(c.assign(a, callVars))
	}
	args := make([]arg, len(x.Args))
	for i, w := range x.Args {
		args[i] = c.word(w)
		f = f.or(args[i].flow)
	}
	ctx := callCtx{in: in, vars: callVars}
	return f.or(c.command(args, ctx))
}

// arg is one resolved word.
type arg struct {
	val    string // value when lit
	lit    bool   // fully static (no expansion or substitution)
	glob   bool   // unquoted glob characters
	tilde  bool   // begins with an unquoted ~
	flow   flow   // what nested substitutions do
	prefix string // the literal text before the first expansion (all of val when lit)
	under  bool   // names entries strictly below val (find -exec {} placeholders)
}

func litArg(s string) arg { return arg{val: s, lit: true} }

// word resolves a shell word statically. $HOME and $PWD resolve when known;
// any other expansion makes the word non-literal. Substitutions inside it are
// classified as commands in their own right.
func (c *classifier) word(w *syntax.Word) arg {
	if w == nil {
		return arg{lit: true}
	}
	var b strings.Builder
	a := arg{lit: true}
	prefixSet := false
	markDynamic := func() {
		if !prefixSet {
			a.prefix, prefixSet = b.String(), true
		}
		a.lit = false
	}
	for i, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			s, g := unescapeUnquoted(p.Value)
			if i == 0 && strings.HasPrefix(p.Value, "~") {
				a.tilde = true
			}
			a.glob = a.glob || g
			b.WriteString(s)
		case *syntax.SglQuoted:
			if p.Dollar {
				b.WriteString(ansiC(p.Value))
			} else {
				b.WriteString(p.Value)
			}
		case *syntax.DblQuoted:
			for _, q := range p.Parts {
				switch qq := q.(type) {
				case *syntax.Lit:
					b.WriteString(unescapeDouble(qq.Value))
				case *syntax.ParamExp:
					v, ok, fl := c.param(qq)
					a.flow = a.flow.or(fl)
					if ok {
						b.WriteString(v)
					} else {
						markDynamic()
					}
				default:
					a.flow = a.flow.or(c.substitutions(q))
					markDynamic()
				}
			}
		case *syntax.ParamExp:
			v, ok, fl := c.param(p)
			a.flow = a.flow.or(fl)
			if ok {
				b.WriteString(v)
			} else {
				markDynamic()
			}
		case *syntax.ExtGlob:
			a.glob = true
			b.WriteString(p.Op.String() + p.Pattern.Value + ")")
		default: // CmdSubst, ProcSubst, ArithmExp, BraceExp
			a.flow = a.flow.or(c.substitutions(part))
			markDynamic()
		}
	}
	a.val = b.String()
	if !prefixSet {
		a.prefix = a.val
	}
	return a
}

// param resolves $HOME / $PWD; everything else is dynamic.
func (c *classifier) param(p *syntax.ParamExp) (string, bool, flow) {
	fl := c.substitutions(p)
	if p.Param == nil || p.Excl || p.Length || p.Width || p.Index != nil || p.Slice != nil || p.Repl != nil || p.Exp != nil || p.Names != 0 {
		return "", false, fl
	}
	switch p.Param.Value {
	case "HOME":
		if c.env.Home != "" && len(c.vars["HOME"]) == 0 {
			return c.env.Home, true, fl
		}
	case "PWD":
		if c.cwd != "" && len(c.vars["PWD"]) == 0 {
			return c.cwd, true, fl
		}
	}
	return "", false, fl
}

// unescapeUnquoted removes backslash escapes from an unquoted literal and
// reports whether it contains unescaped glob or brace-expansion characters.
func unescapeUnquoted(s string) (string, bool) {
	var b strings.Builder
	glob := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '\\' && i+1 < len(s) {
			i++
			if s[i] != '\n' {
				b.WriteByte(s[i])
			}
			continue
		}
		switch ch {
		case '*', '?', '[':
			glob = true
		case '{':
			if j := strings.IndexByte(s[i:], '}'); j > 0 && (strings.Contains(s[i:i+j], ",") || strings.Contains(s[i:i+j], "..")) {
				glob = true
			}
		}
		b.WriteByte(ch)
	}
	return b.String(), glob
}

func unescapeDouble(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && strings.IndexByte("$`\"\\\n", s[i+1]) >= 0 {
			i++
			if s[i] != '\n' {
				b.WriteByte(s[i])
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// ansiC decodes a $'...' string (\n, \xHH, \NNN, \uHHHH ...), so `$'\x72m'`
// is seen as "rm".
func ansiC(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch e := s[i]; e {
		case 'a':
			b.WriteByte(7)
		case 'b':
			b.WriteByte(8)
		case 'e', 'E':
			b.WriteByte(27)
		case 'f':
			b.WriteByte(12)
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case 'v':
			b.WriteByte(11)
		case 'x', 'u', 'U':
			max := map[byte]int{'x': 2, 'u': 4, 'U': 8}[e]
			j := i + 1
			for j < len(s) && j-i-1 < max && isHex(s[j]) {
				j++
			}
			if j == i+1 {
				b.WriteByte('\\')
				b.WriteByte(e)
				continue
			}
			n, _ := strconv.ParseUint(s[i+1:j], 16, 32)
			if e == 'x' {
				b.WriteByte(byte(n))
			} else {
				b.WriteRune(rune(n))
			}
			i = j - 1
		case 'c':
			if i+1 < len(s) {
				i++
				b.WriteByte(s[i] & 0x1f)
			}
		default:
			if e >= '0' && e <= '7' {
				j := i
				for j < len(s) && j-i < 3 && s[j] >= '0' && s[j] <= '7' {
					j++
				}
				n, _ := strconv.ParseUint(s[i:j], 8, 16)
				b.WriteByte(byte(n))
				i = j - 1
				continue
			}
			b.WriteByte(e) // \\ \' \" \? and unknown escapes
		}
	}
	return b.String()
}

func isHex(ch byte) bool {
	return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')
}

// --- recording helpers ---------------------------------------------------------

func clip(s string) string {
	if len(s) <= maxStringLen {
		return s
	}
	cut := maxStringLen
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func addUnique(list *[]string, v string) {
	v = clip(v)
	for _, x := range *list {
		if x == v {
			return
		}
	}
	if len(*list) < maxListLen {
		*list = append(*list, v)
	}
}

func (c *classifier) verb(v action.Verb) {
	if verbRank[v] > verbRank[c.res.Verb] {
		c.res.Verb = v
	}
}

func (c *classifier) op(tag string)    { addUnique(&c.res.Operations, tag) }
func (c *classifier) cmdName(n string) { addUnique(&c.res.Commands, n) }
func (c *classifier) dyn(reason string) {
	c.res.Dynamic = true
	addUnique(&c.res.DynamicReasons, reason)
}

func (c *classifier) extHost(host string) {
	if host == "" {
		return
	}
	if isExternal(host, c.env.InternalHosts) {
		addUnique(&c.res.ExternalHosts, host)
	}
}

func (c *classifier) destructive(cmd, kind, scope, p string) {
	c.op("destructive")
	for _, d := range c.res.Destructive {
		if d.Command == cmd && d.Kind == kind && d.Scope == scope && d.Path == p {
			return
		}
	}
	if len(c.res.Destructive) < maxListLen {
		c.res.Destructive = append(c.res.Destructive, Destructive{Command: clip(cmd), Kind: kind, Scope: scope, Path: clip(p)})
	}
	if p != "" {
		addUnique(&c.res.Paths, p)
	}
}

// tilde returns the word with a leading unquoted ~ kept as "~" (resolved
// later against the known home) and a quoted "~" made explicit.
func (c *classifier) tilde(a arg) string {
	if !a.tilde && strings.HasPrefix(a.val, "~") {
		return "./" + a.val // a quoted ~ is a literal directory named "~"
	}
	return a.val
}

// resolve returns the absolute path of a literal argument (or the argument
// itself when unresolvable) and whether it resolved.
func (c *classifier) resolve(a arg) (string, bool) {
	if !a.lit {
		return "", false
	}
	p := c.tilde(a)
	if a.glob {
		p = globBase(p)
	}
	return cleanAbs(p, c.cwd, c.env.Home)
}

// scope classifies the target of a destructive command.
func (c *classifier) scope(a arg) (string, string) {
	if !a.lit {
		return ScopeUnknown, ""
	}
	p := c.tilde(a)
	if a.glob {
		p = globBase(p)
	}
	if p == "~" || p == "~/" {
		return ScopeCatastrophe, "~"
	}
	abs, ok := cleanAbs(p, c.cwd, c.env.Home)
	if !ok {
		return ScopeUnknown, p
	}
	l := strings.ToLower(abs)
	if abs == "/" || systemTopDirs[l] {
		return ScopeCatastrophe, abs
	}
	if h := c.env.Home; h != "" && within(h, abs) {
		return ScopeCatastrophe, abs // the home directory or one of its ancestors
	}
	proj := c.env.ProjectDir
	if proj != "" && abs != proj && within(proj, abs) {
		return ScopeCatastrophe, abs // an ancestor of the project
	}
	if isTempPath(abs) {
		return ScopeTemp, abs
	}
	if proj == "" {
		return ScopeUnknown, abs
	}
	if abs == proj {
		if a.under {
			return ScopeProject, abs // entries below the project root (find . -name x -delete)
		}
		return ScopeProjectRoot, abs
	}
	if within(abs, proj) {
		rel := strings.TrimPrefix(abs, proj+"/")
		if rel == ".git" || strings.HasPrefix(rel, ".git/") {
			return ScopeProjectRoot, abs
		}
		return ScopeProject, abs
	}
	return ScopeOutside, abs
}

// rmTarget records a destructive filesystem target and, when the target is a
// sensitive path, a sensitive write.
func (c *classifier) rmTarget(cmd, kind string, a arg) {
	sc, p := c.scope(a)
	c.destructive(cmd, kind, sc, p)
	if p != "" {
		if k := sensitiveKind(p); k != "" && k != KindSystem {
			c.sensitiveWrite(p, k)
		}
	}
}

// sensitiveWrite records a write to a sensitive path (or a synthetic target
// such as "crontab") of the given kind.
func (c *classifier) sensitiveWrite(p, kind string) {
	addUnique(&c.res.SensitiveWrites, p)
	addUnique(&c.res.SensitiveKinds, kind)
	c.verb(action.VerbWrite)
}

// sensitiveRead records a read of credentials (a path, or a synthetic
// target such as "keychain").
func (c *classifier) sensitiveRead(p string) {
	addUnique(&c.res.SensitiveReads, p)
}

// writePath records a file the command writes (sensitive, device, path list).
func (c *classifier) writePath(a arg, cmd string) {
	c.verb(action.VerbWrite)
	if !a.lit {
		return
	}
	abs, ok := c.resolve(a)
	p := abs
	if !ok {
		p = c.tilde(a)
	}
	if ok && isBlockDevice(abs) {
		c.destructive(cmd, "disk", ScopeCatastrophe, abs)
		c.verb(action.VerbDelete)
		return
	}
	addUnique(&c.res.Paths, p)
	if k := sensitiveKind(p); k != "" {
		c.sensitiveWrite(p, k)
	}
}

// readPath records a file the command reads; credential files count.
func (c *classifier) readPath(a arg, _ string) bool {
	if !a.lit {
		return false
	}
	abs, ok := c.resolve(a)
	p := abs
	if !ok {
		p = c.tilde(a)
	}
	if sensitiveKind(p) == KindCredentials {
		c.sensitiveRead(p)
		addUnique(&c.res.Paths, p)
		return true
	}
	return false
}

func (c *classifier) finish() ShellResult {
	r := c.res
	if r.Uploads && (len(r.SensitiveReads) > 0 || r.envDump || r.uploadFiles) {
		r.UploadSensitive = true
	}
	if r.Dynamic {
		c.op("dynamic")
	}
	sort.Strings(r.DynamicReasons)
	return *r
}
