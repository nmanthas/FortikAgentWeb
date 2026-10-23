package hook

// git and GitHub CLI: detection patterns for refusal. Force pushes and
// branch deletions are described (operation, remote, branch) so POL-507 can
// refuse them on protected branches; destructive local resets are POL-503.

import (
	"strings"

	"fortik/internal/action"
)

// gitGlobal: git options before the sub-command that take a value.
var gitGlobal = optSpec{shortArg: "Cc", longArg: set("git-dir", "work-tree", "namespace", "exec-path", "config-env", "super-prefix"), stopAtPos: true}

// gitRead: sub-commands that only read the repository (fetch only updates
// remote-tracking refs).
var gitRead = set("status", "diff", "log", "show", "branch", "tag", "remote", "rev-parse", "ls-files",
	"ls-tree", "ls-remote", "blame", "grep", "fetch", "describe", "shortlog", "reflog", "cat-file",
	"rev-list", "show-ref", "for-each-ref", "config", "help", "version", "whatchanged", "name-rev", "merge-base", "count-objects", "check-ignore")

// gitKnown: built-in sub-commands that are neither read-only nor handled
// specially. Any other word may be an alias (`git -c alias.p=push p -f`, or
// one set earlier with `git config alias.x ...`) and is held as dynamic.
var gitKnown = set("add", "commit", "checkout", "switch", "merge", "rebase", "pull", "clone", "init", "stash",
	"cherry-pick", "revert", "restore", "mv", "am", "apply", "worktree", "submodule", "bisect", "notes", "gc",
	"prune", "fsck", "format-patch", "archive", "bundle", "sparse-checkout", "lfs", "maintenance", "mergetool",
	"difftool", "range-diff", "request-pull", "update-index", "hash-object", "read-tree", "write-tree",
	"commit-tree", "pack-refs", "repack", "verify-commit", "verify-tag", "var", "check-attr", "check-ref-format",
	"interpret-trailers", "rerere", "show-branch", "column", "stripspace", "mailinfo", "mailsplit", "credential-cache")

// gitMaxAlias bounds alias expansion (aliases may refer to aliases).
const gitMaxAlias = 4

func registerGit() {
	register(gitCmd, "git")
	register(ghCmd, "gh")
}

func gitCmd(c *classifier, _ string, args []arg, ctx callCtx) flow {
	return c.git(args, ctx, 0)
}

func (c *classifier) git(args []arg, ctx callCtx, depth int) flow {
	g := parseOpts(args, gitGlobal)
	// -c NAME=VALUE: aliases and push refspecs configured on the command line.
	aliases := map[string]arg{}
	cfgPush := false
	for _, v := range g.vals("-c") {
		if !v.lit {
			c.dyn("git -c value is not a literal")
			continue
		}
		k, val, _ := strings.Cut(v.val, "=")
		k = strings.ToLower(k)
		switch {
		case strings.HasPrefix(k, "alias."):
			aliases[strings.TrimPrefix(k, "alias.")] = litArg(val)
		case strings.HasPrefix(k, "remote.") && strings.HasSuffix(k, ".push"), strings.HasPrefix(k, "push."):
			cfgPush = true
		}
	}
	for _, v := range g.vals("--config-env") {
		k, _, _ := strings.Cut(v.val, "=")
		if !v.lit || strings.HasPrefix(strings.ToLower(k), "alias.") || strings.HasSuffix(strings.ToLower(k), ".push") || strings.HasPrefix(strings.ToLower(k), "push.") {
			c.dyn("git --config-env sets an alias or push refspec from the environment")
		}
	}
	rest := g.operands()
	if len(rest) == 0 {
		return flow{}
	}
	if !rest[0].lit {
		c.dyn("git sub-command is not a literal")
		c.verb(action.VerbExecute)
		return flow{}
	}
	sub, sargs := rest[0].val, rest[1:]
	if al, ok := aliases[strings.ToLower(sub)]; ok {
		c.verb(action.VerbExecute)
		if strings.HasPrefix(al.val, "!") {
			// A shell alias: the rest of the line is appended to the script.
			parts := []string{strings.TrimPrefix(al.val, "!")}
			for _, a := range sargs {
				if !a.lit {
					c.dyn("git alias argument is not a literal")
					return flow{}
				}
				parts = append(parts, a.val)
			}
			c.nested(strings.Join(parts, " "))
			return flow{}
		}
		if depth >= gitMaxAlias {
			c.dyn("git alias nested too deep")
			return flow{}
		}
		words := strings.Fields(al.val)
		if len(words) == 0 {
			return flow{}
		}
		// Re-run with the alias expanded (keeping the global options).
		exp := make([]arg, 0, len(args)+len(words))
		exp = append(exp, args[:len(args)-len(rest)]...)
		for _, w := range words {
			exp = append(exp, litArg(w))
		}
		exp = append(exp, sargs...)
		return c.git(exp, ctx, depth+1)
	}
	switch sub {
	case "push", "send-pack":
		gitPush(c, sargs, cfgPush)
	case "reset":
		if hasLit(sargs, "--hard", "--merge", "--keep") {
			c.verb(action.VerbDelete)
			c.destructive("git reset --hard", "git", ScopeProjectRoot, c.cwd)
		} else {
			c.verb(action.VerbWrite)
		}
	case "clean":
		p := parseOpts(sargs, optSpec{shortArg: "eX", longArg: set("exclude")})
		if (p.has("-f", "--force")) && !p.has("-n", "--dry-run") {
			c.verb(action.VerbDelete)
			c.destructive("git clean -f", "git", ScopeProjectRoot, c.cwd)
		}
	case "rm":
		p := parseOpts(sargs, optSpec{longArg: set("pathspec-from-file")})
		if p.has("--cached", "-n", "--dry-run") {
			c.verb(action.VerbWrite)
			break
		}
		c.verb(action.VerbDelete)
		for _, a := range p.operands() {
			c.rmTarget("git rm", "filesystem", a)
		}
		if _, ok := p.val("--pathspec-from-file"); ok {
			c.destructive("git rm", "filesystem", ScopeUnknown, "")
		}
	case "branch", "tag":
		if hasLit(sargs, "-D", "-d", "--delete", "-m", "-M", "-f", "--force") {
			c.verb(action.VerbWrite)
		}
	case "config":
		if !hasLit(sargs, "--get", "--get-all", "--list", "-l", "--get-regexp") && len(sargs) > 1 {
			c.verb(action.VerbWrite)
			if hasLit(sargs, "--global", "--system") {
				c.sensitiveWrite("git config --global", KindPersistence)
			}
		}
	case "remote":
		if len(sargs) > 0 && sargs[0].lit && sargs[0].val != "-v" && sargs[0].val != "show" {
			c.verb(action.VerbWrite)
		}
	default:
		if gitRead[sub] {
			return flow{}
		}
		c.verb(action.VerbWrite)
		if !gitKnown[sub] {
			c.dyn("git sub-command is not built in (may be an alias)")
			c.verb(action.VerbExecute)
		}
	}
	return flow{}
}

func hasLit(args []arg, vals ...string) bool {
	for _, a := range args {
		if !a.lit {
			continue
		}
		for _, v := range vals {
			if a.val == v {
				return true
			}
		}
	}
	return false
}

var gitPushSpec = optSpec{shortArg: "o", longArg: set("repo", "receive-pack", "exec", "push-option", "recurse-submodules")}

// gitPush records each pushed ref: force (-f, --force, --force-with-lease,
// --mirror, +refspec), deletion (--delete, :branch), and the branch (from
// the refspec; HEAD or no refspec = the current branch, unknown here).
// cfgPush: a push refspec or push.* setting was given with -c, so the pushed
// refs (and whether they are forced) come from configuration: force_push to
// an unresolved branch.
func gitPush(c *classifier, args []arg, cfgPush bool) {
	c.verb(action.VerbWrite)
	p := parseOpts(args, gitPushSpec)
	force := p.has("-f", "--force", "--mirror") || p.hasPrefix("--force-with-lease") || p.hasPrefix("--force-if-includes")
	del := p.has("-d", "--delete")
	ops := p.operands()
	remote := ""
	if len(ops) > 0 {
		if ops[0].lit {
			remote = ops[0].val
		}
		ops = ops[1:]
	}
	if r, ok := p.val("--repo"); ok && r.lit {
		remote = r.val
	}
	add := func(branch string, f, d bool) {
		op := "push"
		switch {
		case d:
			op = "delete_branch"
		case f:
			op = "force_push"
		}
		c.op("git_" + op)
		c.res.Git = append(c.res.Git, GitOp{Operation: op, Remote: clip(remote), Branch: clip(branch)})
	}
	if p.has("--all", "--mirror", "--branches") {
		add("*", force, del)
	}
	if len(ops) == 0 && !p.has("--all", "--mirror", "--branches", "--tags") {
		add("", force || cfgPush, del)
	}
	for _, r := range ops {
		if !r.lit {
			add("", force, del)
			continue
		}
		spec := r.val
		f := force
		if strings.HasPrefix(spec, "+") {
			f, spec = true, spec[1:]
		}
		src, dst, hasColon := strings.Cut(spec, ":")
		d := del || (hasColon && src == "")
		branch := src
		if hasColon {
			branch = dst
		}
		if branch == "HEAD" || branch == "@" {
			branch = ""
		}
		add(strings.TrimPrefix(branch, "refs/heads/"), f, d)
	}
}

// ghOps maps "gh <group> <verb>" to an operation; read operations are not
// listed (view, list, status, diff, checks, clone ...).
var ghOps = map[string]string{
	"pr merge": "merge_pr", "pr create": "create_pr", "pr close": "close_pr", "pr edit": "update_pr",
	"pr comment": "comment", "pr review": "comment", "issue create": "create_issue", "issue close": "close_issue",
	"issue comment": "comment", "issue delete": "delete_issue", "repo delete": "delete_repo",
	"repo archive": "archive_repo", "repo edit": "edit_repo", "repo create": "create_repo", "repo rename": "edit_repo",
	"secret set": "set_secret", "secret delete": "delete_secret", "secret remove": "delete_secret",
	"variable set": "set_variable", "variable delete": "set_variable", "workflow run": "run_workflow",
	"workflow enable": "run_workflow", "run rerun": "run_workflow", "release delete": "delete_release",
	"release create": "create_release", "repo deploy-key": "add_deploy_key", "ssh-key add": "add_deploy_key",
	"auth token": "read_token", "auth login": "auth",
}

func ghCmd(c *classifier, _ string, args []arg, _ callCtx) flow {
	p := parseOpts(args, optSpec{shortArg: "RXf", longArg: set("repo", "method", "field", "raw-field", "jq", "hostname")})
	repo := ""
	if r, ok := p.val("-R", "--repo"); ok && r.lit {
		repo = r.val
	}
	ops := p.operands()
	if len(ops) == 0 {
		return flow{}
	}
	for _, o := range ops[:min(2, len(ops))] {
		if !o.lit {
			c.dyn("gh sub-command is not a literal")
			c.verb(action.VerbExecute)
			return flow{}
		}
	}
	key := ops[0].val
	if len(ops) > 1 {
		key += " " + ops[1].val
	}
	op, ok := ghOps[key]
	if ops[0].val == "api" {
		m, _ := p.val("-X", "--method")
		if (m.lit && m.val != "" && !strings.EqualFold(m.val, "GET")) || p.has("-f", "-F", "--field", "--raw-field") {
			op, ok = "api_write", true
		}
	}
	if !ok {
		return flow{}
	}
	switch {
	case strings.HasPrefix(op, "delete_"):
		c.verb(action.VerbDelete)
	case op == "read_token":
		c.sensitiveRead("gh auth token")
		return flow{}
	default:
		c.verb(action.VerbWrite)
	}
	c.op("gh_" + op)
	c.res.GH = append(c.res.GH, GHOp{Operation: op, Repo: clip(repo)})
	return flow{}
}
