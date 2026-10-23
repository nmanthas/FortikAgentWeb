package hook

// Destructive filesystem and disk commands: detection patterns for refusal.
// These tables name commands so the hook can RECOGNISE them and policy
// (POL-503) can refuse or hold them; Fortik never runs them.

import (
	"strings"

	"fortik/internal/action"
)

// diskTools rewrite partition tables or file systems (always catastrophic).
var diskTools = []string{"wipefs", "fdisk", "sfdisk", "gdisk", "sgdisk", "parted", "newfs", "mke2fs", "mkswap", "blkdiscard"}

// diskutilDestructive: diskutil verbs that erase or repartition a disk.
var diskutilDestructive = set("erasedisk", "erasevolume", "zerodisk", "randomdisk", "secureerase", "partitiondisk", "reformat", "apfs")

// powerCommands stop the machine.
var powerCommands = []string{"shutdown", "reboot", "halt", "poweroff"}

func registerFS() {
	register(rmCmd, "rm", "rmdir", "unlink", "shred", "srm")
	register(findCmd, "find")
	register(ddCmd, "dd")
	register(diskTool, diskTools...)
	register(diskutilCmd, "diskutil")
	register(truncateCmd, "truncate")
	register(chmodCmd, "chmod", "chown", "chgrp")
	register(powerCmd, powerCommands...)
}

// rmCmd: every operand is a destroyed path, scoped (project, temp, outside,
// catastrophic) by classifier.scope.
func rmCmd(c *classifier, name string, args []arg, _ callCtx) flow {
	c.verb(action.VerbDelete)
	sp := optSpec{}
	if name == "shred" {
		sp = optSpec{shortArg: "nsr", longArg: set("iterations", "size", "random-source")}
	}
	ops := parseOpts(args, sp).operands()
	if len(ops) == 0 {
		return flow{}
	}
	for _, a := range ops {
		c.rmTarget(name, "filesystem", a)
	}
	return flow{}
}

// findDestructiveExec: commands run by find -exec that destroy their {} arg.
var findDestructiveExec = set("rm", "shred", "unlink", "rmdir", "srm", "truncate")

// findCmd: READ unless -delete or -exec/-execdir/-ok runs something; the
// destroyed entries are below the starting points.
func findCmd(c *classifier, _ string, args []arg, ctx callCtx) flow {
	var starts []arg
	i := 0
	for ; i < len(args); i++ {
		a := args[i]
		if a.lit && (a.val == "-H" || a.val == "-L" || a.val == "-P") {
			continue
		}
		if a.lit && (strings.HasPrefix(a.val, "-") || a.val == "(" || a.val == "!") {
			break
		}
		starts = append(starts, a)
	}
	if len(starts) == 0 {
		starts = []arg{litArg(".")}
	}
	destroy := func() {
		c.verb(action.VerbDelete)
		for _, s := range starts {
			s.under = true
			c.rmTarget("find", "filesystem", s)
		}
	}
	var f flow
	for ; i < len(args); i++ {
		a := args[i]
		if !a.lit {
			continue
		}
		switch a.val {
		case "-delete":
			destroy()
		case "-exec", "-execdir", "-ok", "-okdir":
			j := i + 1
			for j < len(args) && !(args[j].lit && (args[j].val == ";" || args[j].val == "+")) {
				j++
			}
			sub := append([]arg(nil), args[i+1:j]...)
			i = j
			if len(sub) == 0 {
				continue
			}
			if sub[0].lit && findDestructiveExec[strings.ToLower(lastSeg(sub[0].val))] {
				destroy()
				continue
			}
			for k := range sub {
				if sub[k].lit && strings.Contains(sub[k].val, "{}") {
					sub[k] = arg{} // the found path: not a literal
				}
			}
			f = f.or(c.command(sub, callCtx{vars: ctx.vars}))
		case "-fprint", "-fprintf", "-fls":
			if i+1 < len(args) {
				i++
				c.writePath(args[i], "find")
			}
		}
	}
	return f
}

func lastSeg(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

// ddCmd: of= is written (a block device destroys a file system); if= read.
func ddCmd(c *classifier, _ string, args []arg, _ callCtx) flow {
	c.verb(action.VerbWrite)
	for _, a := range args {
		if !a.lit {
			continue
		}
		if v, ok := strings.CutPrefix(a.val, "of="); ok {
			c.writePath(litArg(v), "dd")
		}
		if v, ok := strings.CutPrefix(a.val, "if="); ok {
			c.readPath(litArg(v), "dd")
		}
	}
	return flow{}
}

// diskTool: file system creation / partitioning, always catastrophic.
func diskTool(c *classifier, name string, args []arg, _ callCtx) flow {
	c.verb(action.VerbDelete)
	target := ""
	for _, a := range args {
		if a.lit && strings.HasPrefix(a.val, "/dev/") {
			target = a.val
		}
	}
	c.destructive(name, "disk", ScopeCatastrophe, target)
	return flow{}
}

func diskutilCmd(c *classifier, name string, args []arg, ctx callCtx) flow {
	if len(args) > 0 && args[0].lit && diskutilDestructive[strings.ToLower(args[0].val)] {
		return diskTool(c, name, args[1:], ctx)
	}
	c.verb(action.VerbExecute)
	return flow{}
}

// truncateCmd empties or cuts files: destructive per path.
func truncateCmd(c *classifier, name string, args []arg, _ callCtx) flow {
	c.verb(action.VerbDelete)
	for _, a := range parseOpts(args, optSpec{shortArg: "sr", longArg: set("size", "reference")}).operands() {
		c.rmTarget(name, "filesystem", a)
	}
	return flow{}
}

// chmodCmd: recursive permission/owner changes are destructive (scoped);
// single-file changes are writes (sensitive paths count).
func chmodCmd(c *classifier, name string, args []arg, _ callCtx) flow {
	c.verb(action.VerbWrite)
	p := parseOpts(args, optSpec{longArg: set("reference", "from")})
	ops := p.operands()
	if _, ok := p.val("--reference"); !ok && len(ops) > 0 {
		ops = ops[1:] // mode or owner
	}
	recursive := p.has("-R", "--recursive")
	for _, a := range ops {
		if recursive {
			c.rmTarget(name+" -R", "permissions", a)
		} else {
			c.writePath(a, name)
		}
	}
	return flow{}
}

func powerCmd(c *classifier, name string, _ []arg, _ callCtx) flow {
	c.verb(action.VerbExecute)
	c.destructive(name, "power", ScopeCatastrophe, "")
	return flow{}
}
