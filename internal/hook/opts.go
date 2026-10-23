package hook

import "strings"

// optSpec describes a command's option syntax well enough to tell option
// values from operands.
type optSpec struct {
	shortArg  string          // short options that take a value (-o FILE, -oFILE)
	shortOpt  string          // short options whose value must be attached (mysql -pSECRET)
	longArg   map[string]bool // long options (without "--") that take a value
	stopAtPos bool            // options end at the first operand (sub-command CLIs)
}

type flagv struct {
	name string // "-x" or "--long"
	val  arg
	has  bool
}

type parsed struct {
	pos   []arg
	flags []flagv
	rest  []arg // stopAtPos: the first operand and everything after it
}

func set(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

// parseOpts splits args into options and operands (GNU style: options may
// follow operands unless stopAtPos; "--" ends options). Non-literal words
// are operands.
func parseOpts(args []arg, sp optSpec) parsed {
	var p parsed
	end := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		s := a.val
		if !a.lit || end || s == "-" || !strings.HasPrefix(s, "-") {
			if sp.stopAtPos {
				p.rest = args[i:]
				return p
			}
			p.pos = append(p.pos, a)
			continue
		}
		if s == "--" {
			end = true
			continue
		}
		if strings.HasPrefix(s, "--") {
			name, val, eq := strings.Cut(s[2:], "=")
			switch {
			case eq:
				p.flags = append(p.flags, flagv{name: "--" + name, val: litArg(val), has: true})
			case sp.longArg[name] && i+1 < len(args):
				i++
				p.flags = append(p.flags, flagv{name: "--" + name, val: args[i], has: true})
			default:
				p.flags = append(p.flags, flagv{name: "--" + name})
			}
			continue
		}
		for j := 1; j < len(s); j++ {
			ch := s[j]
			name := "-" + string(ch)
			if strings.IndexByte(sp.shortArg, ch) >= 0 {
				switch {
				case j+1 < len(s):
					p.flags = append(p.flags, flagv{name: name, val: litArg(s[j+1:]), has: true})
				case i+1 < len(args):
					i++
					p.flags = append(p.flags, flagv{name: name, val: args[i], has: true})
				default:
					p.flags = append(p.flags, flagv{name: name})
				}
				break
			}
			if strings.IndexByte(sp.shortOpt, ch) >= 0 {
				if j+1 < len(s) {
					p.flags = append(p.flags, flagv{name: name, val: litArg(s[j+1:]), has: true})
				} else {
					p.flags = append(p.flags, flagv{name: name})
				}
				break
			}
			p.flags = append(p.flags, flagv{name: name})
		}
	}
	return p
}

func (p parsed) has(names ...string) bool {
	for _, f := range p.flags {
		for _, n := range names {
			if f.name == n {
				return true
			}
		}
	}
	return false
}

// hasPrefix reports a long option starting with prefix (--force-with-lease=...).
func (p parsed) hasPrefix(prefix string) bool {
	for _, f := range p.flags {
		if strings.HasPrefix(f.name, prefix) {
			return true
		}
	}
	return false
}

func (p parsed) vals(names ...string) []arg {
	var out []arg
	for _, f := range p.flags {
		if !f.has {
			continue
		}
		for _, n := range names {
			if f.name == n {
				out = append(out, f.val)
			}
		}
	}
	return out
}

func (p parsed) val(names ...string) (arg, bool) {
	v := p.vals(names...)
	if len(v) == 0 {
		return arg{}, false
	}
	return v[len(v)-1], true
}

// operands returns the operands, or the sub-command remainder when stopAtPos.
func (p parsed) operands() []arg {
	if p.rest != nil {
		return p.rest
	}
	return p.pos
}

// litVal returns the literal value of a, or ok=false.
func litVal(a arg) (string, bool) { return a.val, a.lit }
