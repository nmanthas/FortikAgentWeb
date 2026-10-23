package hook

import (
	"path"
	"strings"
)

// Sensitive path kinds (target.sensitive_kind / shell sensitive_writes).
const (
	KindCredentials = "credentials"  // keys, tokens, .env files, cloud credentials
	KindAgentConfig = "agent_config" // Claude Code settings (could disable this hook)
	KindWorkflow    = "workflow"     // .github/workflows (CI with repository secrets)
	KindPersistence = "persistence"  // shell rc files, git hooks/config, launch agents, cron
	KindSystem      = "system"       // /etc, /usr, /bin...
)

// Scopes of a destructive command's target (target.destructive[].scope).
const (
	ScopeProject     = "project"         // inside the project: allowed
	ScopeProjectRoot = "project_root"    // the project itself or its .git: hold
	ScopeOutside     = "outside_project" // elsewhere on the machine: hold
	ScopeUnknown     = "unknown"         // not a literal / cannot be resolved: hold
	ScopeCatastrophe = "catastrophic"    // /, home, system directories, an ancestor of the project: red
	ScopeTemp        = "temp"            // below a temporary directory (/tmp/x): allowed
	ScopeRemote      = "remote"          // remote infrastructure (kubectl delete, terraform destroy)
)

// tempRoots are shared temporary directories: removing something below one
// of them is allowed, removing the directory itself is not.
var tempRoots = []string{"/tmp", "/private/tmp", "/var/tmp", "/private/var/tmp", "/private/var/folders", "/var/folders"}

func isTempPath(abs string) bool {
	for _, r := range tempRoots {
		if strings.HasPrefix(abs, r+"/") {
			return true
		}
	}
	return false
}

var systemTopDirs = map[string]bool{
	"/bin": true, "/boot": true, "/dev": true, "/etc": true, "/home": true, "/lib": true, "/lib64": true,
	"/opt": true, "/proc": true, "/root": true, "/sbin": true, "/srv": true, "/sys": true, "/usr": true,
	"/var": true, "/tmp": false, "/users": true, "/system": true, "/library": true, "/applications": true,
	"/private": true, "/volumes": true, "/cores": true, "/snap": true, "/mnt": true, "/media": true,
	"/usr/bin": true, "/usr/lib": true, "/usr/local": true, "/usr/sbin": true, "/var/lib": true,
	"/private/etc": true, "/private/var": true,
}

// within reports whether p is base or below it (both cleaned absolute paths).
func within(p, base string) bool {
	if base == "/" {
		return strings.HasPrefix(p, "/")
	}
	return p == base || strings.HasPrefix(p, base+"/")
}

// cleanAbs joins p onto dir (when relative) and cleans it. ok is false when
// p is relative and dir unknown, or p needs a home directory that is unknown.
func cleanAbs(p, dir, home string) (string, bool) {
	switch {
	case p == "":
		return "", false
	case p == "~" || strings.HasPrefix(p, "~/"):
		if home == "" {
			return "", false
		}
		return path.Clean(home + "/" + strings.TrimPrefix(p, "~")), true
	case strings.HasPrefix(p, "~"): // ~user
		return "", false
	case strings.HasPrefix(p, "/"):
		return path.Clean(p), true
	case dir == "":
		return "", false
	}
	return path.Clean(dir + "/" + p), true
}

// globBase returns the literal directory prefix of a glob ("/*" -> "/",
// "build/*.o" -> "build", "*" -> ".").
func globBase(p string) string {
	segs := strings.Split(p, "/")
	var keep []string
	for i, s := range segs {
		if strings.ContainsAny(s, "*?[{") {
			break
		}
		if i == 0 && s == "" {
			keep = append(keep, "")
			continue
		}
		keep = append(keep, s)
	}
	switch {
	case len(keep) == 0:
		return "."
	case len(keep) == 1 && keep[0] == "":
		return "/"
	}
	return strings.Join(keep, "/")
}

// sensitiveKind classifies a path (absolute when resolvable, otherwise as
// written). Matching is case-insensitive: macOS file systems are.
func sensitiveKind(p string) string {
	if p == "" {
		return ""
	}
	l := strings.ToLower(path.Clean(p))
	segs := strings.Split(l, "/")
	base := segs[len(segs)-1]
	has := func(sub string) bool { return strings.Contains("/"+l+"/", sub) }

	// Credentials.
	for _, s := range segs {
		switch s {
		case ".ssh", ".aws", ".gnupg", ".kube", ".azure", ".password-store", ".docker-credentials":
			return KindCredentials
		}
	}
	if has("/.config/gcloud/") || has("/.config/gh/") || has("/.docker/config.json/") || has("/.config/op/") {
		return KindCredentials
	}
	if base == ".env" || strings.HasSuffix(base, ".env") || strings.HasPrefix(base, ".env.") {
		safe := false
		for _, suf := range []string{".example", ".sample", ".template", ".dist", ".defaults"} {
			if strings.HasSuffix(base, suf) {
				safe = true
			}
		}
		if !safe {
			return KindCredentials
		}
	}
	for _, suf := range []string{".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".ppk", ".kdbx", ".tfstate", ".tfstate.backup"} {
		if strings.HasSuffix(base, suf) {
			return KindCredentials
		}
	}
	for _, pre := range []string{"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "client_secret", "service-account"} {
		if strings.HasPrefix(base, pre) && !strings.HasSuffix(base, ".pub") {
			return KindCredentials
		}
	}
	switch base {
	case ".netrc", "_netrc", ".pgpass", ".npmrc", ".pypirc", ".git-credentials", ".vault-token", "credentials",
		"credentials.json", "credentials.yml", "credentials.yaml", "secrets.json", "secrets.yml", "secrets.yaml",
		".htpasswd", "master.key", ".boto", ".s3cfg", "kubeconfig", "auth.json":
		return KindCredentials
	case "shadow", "gshadow", "master.passwd", "sudoers":
		if strings.HasPrefix(l, "/etc/") || strings.HasPrefix(l, "/private/etc/") {
			return KindCredentials
		}
	}

	// Claude Code's own settings: writing them could remove this hook.
	if has("/.claude/settings.json/") || has("/.claude/settings.local.json/") || base == "managed-settings.json" ||
		has("/library/application support/claudecode/") || strings.HasPrefix(l, "/etc/claude-code/") {
		return KindAgentConfig
	}

	if has("/.github/workflows/") || strings.HasPrefix(l, ".github/workflows/") || l == ".github/workflows" {
		return KindWorkflow
	}

	switch base {
	case ".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile", ".zshrc", ".zprofile", ".zshenv",
		".zlogin", ".cshrc", ".tcshrc", ".login", ".inputrc", ".gitconfig":
		return KindPersistence
	}
	if has("/.git/hooks/") || strings.HasPrefix(l, ".git/hooks/") || strings.HasSuffix(l, ".git/config") ||
		has("/.config/fish/") || has("/library/launchagents/") || has("/library/launchdaemons/") ||
		has("/.config/autostart/") || has("/var/spool/cron/") || strings.HasPrefix(l, "/etc/cron") {
		return KindPersistence
	}

	for _, pre := range []string{"/etc/", "/usr/", "/bin/", "/sbin/", "/boot/", "/lib/", "/lib64/", "/system/", "/private/etc/", "/library/"} {
		if strings.HasPrefix(l+"/", pre) {
			return KindSystem
		}
	}
	return ""
}

// isBlockDevice reports whether p names a disk device (writing it destroys
// a file system).
func isBlockDevice(p string) bool {
	l := strings.ToLower(p)
	if !strings.HasPrefix(l, "/dev/") {
		return false
	}
	for _, pre := range []string{"/dev/sd", "/dev/hd", "/dev/vd", "/dev/xvd", "/dev/nvme", "/dev/disk", "/dev/rdisk", "/dev/mmcblk", "/dev/md", "/dev/dm-", "/dev/mapper/", "/dev/loop"} {
		if strings.HasPrefix(l, pre) {
			return true
		}
	}
	return false
}

// harmlessDevice: redirect targets that write nowhere.
func harmlessDevice(p string) bool {
	switch p {
	case "/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty", "/dev/zero":
		return true
	}
	return strings.HasPrefix(p, "/dev/fd/") || strings.HasPrefix(p, "/dev/pts/")
}
