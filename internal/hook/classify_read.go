package hook

// Read-only commands and simple file writers (detection patterns for
// refusal: credential reads and sensitive-path writes are what policy
// looks for; nothing here runs a command).

import (
	"strings"

	"fortik/internal/action"
)

// readCommands only read (or print). File operands are checked for
// credential files (POL-512).
var readCommands = []string{
	"ls", "cat", "head", "tail", "grep", "egrep", "fgrep", "rg", "ag", "ack", "pwd", "echo", "printf",
	"wc", "which", "whereis", "type", "file", "stat", "du", "df", "tree", "less", "more", "sort", "uniq",
	"cut", "tr", "diff", "cmp", "comm", "basename", "dirname", "realpath", "readlink", "date", "whoami",
	"id", "uname", "hostname", "true", "false", "test", "[", "jq", "yq", "column", "nl", "fold", "rev",
	"tac", "od", "hexdump", "strings", "md5", "md5sum", "sha1sum", "sha256sum", "shasum", "cksum",
	"sleep", "seq", "yes", "expr", "bc", "fd", "fzf", "bat", "exa", "eza", "lsof", "ps", "top", "uptime",
	"history", "alias", "hash", "help", "man", "info", "tput", "clear", "awk", "gawk", "zcat", "lscpu",
	"set", "unset", "shift", "read", "wait", "jobs", "ulimit", "umask", "getconf", "locale", "tty",
}

// envDumpCommands print the environment (which may hold secrets).
var envDumpCommands = []string{"printenv", "export", "declare", "typeset"}

// decoders de-obfuscate their input (output piped to a shell = dynamic).
var decoders = map[string][]string{
	"base64":   {"-d", "-D", "--decode"},
	"base32":   {"-d", "--decode"},
	"xxd":      {"-r"},
	"uudecode": {""},
	"gunzip":   {""}, "zcat": {""}, "gzip": {"-d"}, "bunzip2": {""}, "xz": {"-d"}, "openssl": {"-d"},
}

func registerRead() {
	register(readCmd, readCommands...)
	register(envDump, envDumpCommands...)
	register(cdCmd, "cd", "pushd", "popd")
	register(decodeCmd, "base64", "base32", "xxd", "uudecode", "gunzip", "gzip", "bunzip2", "xz")
	register(writeAll, "touch", "mkdir", "ln", "install", "mktemp", "chflags", "setfacl", "xattr")
	register(cpCmd, "cp", "mv", "rename")
	register(teeCmd, "tee")
	register(sedCmd, "sed", "perl")
	register(crontabCmd, "crontab")
	register(securityCmd, "security")
}

func readCmd(c *classifier, _ string, args []arg, _ callCtx) flow {
	for _, a := range args {
		if a.lit && !strings.HasPrefix(a.val, "-") {
			c.readPath(a, "read")
		}
	}
	return flow{}
}

func envDump(c *classifier, name string, args []arg, _ callCtx) flow {
	if name == "printenv" || len(args) == 0 || (len(args) == 1 && args[0].val == "-p") {
		c.res.envDump = true
	}
	return flow{}
}

func decodeCmd(c *classifier, name string, args []arg, _ callCtx) flow {
	flags := decoders[name]
	for _, f := range flags {
		if f == "" {
			return flow{decode: true}
		}
		for _, a := range args {
			if a.lit && (a.val == f || (strings.HasPrefix(a.val, "-") && !strings.HasPrefix(a.val, "--") && strings.Contains(a.val, strings.TrimPrefix(f, "-")))) {
				return flow{decode: true}
			}
		}
	}
	readCmd(c, name, args, callCtx{})
	return flow{}
}

// writeAll treats every operand as a written path.
func writeAll(c *classifier, name string, args []arg, _ callCtx) flow {
	c.verb(action.VerbWrite)
	for _, a := range parseOpts(args, optSpec{shortArg: "mtg", longArg: set("mode", "target-directory")}).operands() {
		c.writePath(a, name)
	}
	return flow{}
}

// cpCmd: sources are read (credentials count), sources of mv and the
// destination are written.
func cpCmd(c *classifier, name string, args []arg, _ callCtx) flow {
	c.verb(action.VerbWrite)
	p := parseOpts(args, optSpec{shortArg: "tS", longArg: set("target-directory", "suffix", "backup")})
	ops := p.operands()
	if t, ok := p.val("-t", "--target-directory"); ok {
		ops = append(ops, t)
	}
	for i, a := range ops {
		if i == len(ops)-1 || name != "cp" {
			c.writePath(a, name)
		} else {
			c.readPath(a, name)
		}
	}
	return flow{}
}

func teeCmd(c *classifier, name string, args []arg, _ callCtx) flow {
	for _, a := range parseOpts(args, optSpec{}).operands() {
		c.writePath(a, name)
	}
	return flow{}
}

// sedCmd: in-place editing (-i) writes its file operands.
func sedCmd(c *classifier, name string, args []arg, _ callCtx) flow {
	p := parseOpts(args, optSpec{shortArg: "efE", longArg: set("expression", "file")})
	inPlace := p.hasPrefix("--in-place")
	for _, a := range args {
		if a.lit && strings.HasPrefix(a.val, "-") && !strings.HasPrefix(a.val, "--") && strings.Contains(a.val, "i") {
			inPlace = true
		}
	}
	ops := p.operands()
	if len(p.vals("-e", "--expression", "-f", "--file")) == 0 && len(ops) > 0 {
		ops = ops[1:] // the script
	}
	if name == "perl" && !inPlace {
		c.verb(action.VerbExecute)
		return flow{}
	}
	for _, a := range ops {
		if inPlace {
			c.writePath(a, name)
		} else {
			c.readPath(a, name)
		}
	}
	return flow{}
}

// crontabCmd: installing a crontab is persistence; -l only lists.
func crontabCmd(c *classifier, _ string, args []arg, _ callCtx) flow {
	for _, a := range args {
		if a.lit && a.val == "-l" {
			return flow{}
		}
	}
	c.sensitiveWrite("crontab", KindPersistence)
	return flow{}
}

// securityCmd: macOS keychain secret extraction is a credential read.
func securityCmd(c *classifier, _ string, args []arg, _ callCtx) flow {
	c.verb(action.VerbExecute)
	if len(args) > 0 && args[0].lit && strings.HasPrefix(args[0].val, "find-") && strings.HasSuffix(args[0].val, "-password") {
		c.sensitiveRead("keychain")
	}
	return flow{}
}
