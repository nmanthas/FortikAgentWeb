package hook

// Cloud and infrastructure CLIs: detection patterns for refusal. The aws CLI
// is mapped onto IAM-style actions (s3 rm -> s3:DeleteObject, ec2
// terminate-instances -> ec2:TerminateInstances) so POL-508 can judge it with
// the AWS rule vocabulary; kubectl/terraform/helm/docker deletions are
// destructive infrastructure (POL-503). Nothing is executed.

import (
	"strings"

	"fortik/internal/action"
)

// awsGlobal: aws CLI global options that take a value.
var awsGlobal = optSpec{longArg: set("profile", "region", "output", "endpoint-url", "query", "cli-read-timeout", "cli-connect-timeout", "ca-bundle", "color", "cli-binary-format"), stopAtPos: true}

// awsServiceAlias: CLI service names whose IAM prefix differs.
var awsServiceAlias = map[string]string{"s3api": "s3", "s3control": "s3", "configservice": "config", "elbv2": "elasticloadbalancing", "elb": "elasticloadbalancing"}

// awsS3High: the high-level `aws s3` commands.
var awsS3High = map[string]string{"ls": "s3:ListBucket", "mb": "s3:CreateBucket", "rb": "s3:DeleteBucket", "rm": "s3:DeleteObject", "presign": "s3:GetObject", "website": "s3:PutBucketWebsite"}

// infraDeletes: "<tool> <sub-command>" pairs that destroy remote
// infrastructure.
var infraDeletes = set("kubectl delete", "kubectl drain", "kubectl replace", "helm uninstall", "helm delete", "terraform destroy",
	"pulumi destroy", "cdk destroy", "eksctl delete", "gcloud delete", "az delete", "doctl delete", "flyctl destroy", "heroku destroy")

func registerCloud() {
	register(awsCmd, "aws")
	register(infraCmd, "kubectl", "helm", "terraform", "tofu", "pulumi", "cdk", "eksctl", "gcloud", "az", "doctl", "flyctl", "heroku")
	register(dockerCmd, "docker", "podman")
}

func awsCmd(c *classifier, _ string, args []arg, _ callCtx) flow {
	c.op("aws")
	rest := parseOpts(args, awsGlobal).operands()
	if len(rest) < 2 {
		if len(rest) == 1 && rest[0].lit && rest[0].val == "configure" {
			c.sensitiveWrite("~/.aws/credentials", KindCredentials)
		}
		return flow{}
	}
	if !rest[0].lit || !rest[1].lit {
		c.dyn("aws service or operation is not a literal")
		c.verb(action.VerbExecute)
		return flow{}
	}
	svc, op := strings.ToLower(rest[0].val), strings.ToLower(rest[1].val)
	if svc == "configure" {
		if op != "list" && op != "get" {
			c.sensitiveWrite("~/.aws/credentials", KindCredentials)
		}
		return flow{}
	}
	var acts []string
	if svc == "s3" {
		acts = awsS3(c, op, rest[2:])
	} else {
		if a, ok := awsServiceAlias[svc]; ok {
			svc = a
		}
		acts = []string{svc + ":" + camel(op)}
	}
	for _, a := range acts {
		addUnique(&c.res.AWSActions, a)
		c.verb(awsVerb(a))
	}
	c.extHost("amazonaws.com")
	return flow{}
}

// awsS3 maps `aws s3 cp/mv/sync` by direction: to s3:// is PutObject, from
// s3:// to a local path is GetObject (the local path is written).
func awsS3(c *classifier, op string, args []arg) []string {
	if a, ok := awsS3High[op]; ok {
		return []string{a}
	}
	if op != "cp" && op != "mv" && op != "sync" {
		return []string{"s3:" + camel(op)}
	}
	ops := parseOpts(args, optSpec{longArg: set("exclude", "include", "acl", "storage-class", "sse", "sse-kms-key-id", "content-type", "cache-control", "expires", "grants", "metadata")}).operands()
	if len(ops) < 2 {
		return []string{"s3:PutObject"}
	}
	src, dst := ops[0], ops[len(ops)-1]
	isS3 := func(a arg) bool { return !a.lit || strings.HasPrefix(strings.ToLower(a.val), "s3://") }
	var out []string
	if isS3(dst) {
		out = append(out, "s3:PutObject")
		if !isS3(src) && c.readPath(src, "aws s3") {
			c.res.uploadFiles = true
		}
	} else {
		out = append(out, "s3:GetObject")
		c.writePath(dst, "aws s3")
	}
	if op == "mv" && isS3(src) {
		out = append(out, "s3:DeleteObject")
	}
	for _, a := range args {
		if a.lit && a.val == "--delete" {
			out = append(out, "s3:DeleteObject")
		}
	}
	return out
}

// awsVerb: reads, deletions, identity changes (GRANT) and other writes.
func awsVerb(a string) action.Verb {
	svc, op, _ := strings.Cut(strings.ToLower(a), ":")
	for _, p := range []string{"get", "list", "describe", "head", "lookup", "batchget", "scan", "query", "select"} {
		if strings.HasPrefix(op, p) && op != "getsessiontoken" && op != "getfederationtoken" {
			return action.VerbRead
		}
	}
	for _, p := range []string{"delete", "terminate", "remove", "purge", "destroy", "deregister"} {
		if strings.Contains(op, p) {
			return action.VerbDelete
		}
	}
	if svc == "iam" || svc == "organizations" || svc == "sso" || svc == "sts" {
		return action.VerbGrant
	}
	return action.VerbWrite
}

// camel turns a CLI operation into its API name: terminate-instances ->
// TerminateInstances.
func camel(op string) string {
	var b strings.Builder
	for _, part := range strings.Split(op, "-") {
		if part == "" {
			continue
		}
		b.WriteString(strings.ToUpper(part[:1]) + part[1:])
	}
	return b.String()
}

// infraCmd: deletions of remote infrastructure; everything else EXECUTE.
func infraCmd(c *classifier, name string, args []arg, ctx callCtx) flow {
	c.verb(action.VerbExecute)
	tool := name
	if tool == "tofu" {
		tool = "terraform"
	}
	for i, a := range args {
		if !a.lit || strings.HasPrefix(a.val, "-") {
			continue
		}
		sub := strings.ToLower(a.val)
		if tool == "kubectl" && (sub == "exec" || sub == "run" || sub == "debug") {
			// The container command follows "--": classify it.
			for j := i + 1; j < len(args); j++ {
				if args[j].lit && args[j].val == "--" {
					if j+1 < len(args) {
						return c.command(args[j+1:], callCtx{in: ctx.in, vars: map[string]arg{}})
					}
					break
				}
			}
			return flow{}
		}
		if infraDeletes[tool+" "+sub] || (sub == "apply" && tool == "terraform" && hasLit(args[i:], "-destroy")) {
			c.verb(action.VerbDelete)
			c.destructive(tool+" "+sub, "infra", ScopeRemote, "")
			return flow{}
		}
		if tool != "gcloud" && tool != "az" && tool != "doctl" {
			break // the first word is the sub-command; cloud CLIs nest groups
		}
	}
	return flow{}
}

// dockerCmd: pruning everything (system prune -a, volume prune) destroys
// local state outside the project: held.
// dockerRunSpec / dockerExecSpec: options that take a value, so the image
// (or container) and the command run inside it can be found.
var dockerRunSpec = optSpec{shortArg: "acehlmpuvw", longArg: set("add-host", "attach", "cap-add", "cap-drop", "cgroup-parent",
	"cidfile", "cpu-shares", "cpus", "cpuset-cpus", "device", "dns", "entrypoint", "env", "env-file", "expose", "gpus",
	"group-add", "health-cmd", "hostname", "ip", "label", "label-file", "link", "log-driver", "log-opt", "mac-address",
	"memory", "mount", "name", "network", "network-alias", "platform", "publish", "pull", "restart", "runtime",
	"security-opt", "shm-size", "stop-signal", "stop-timeout", "storage-opt", "sysctl", "tmpfs", "ulimit", "user",
	"userns", "uts", "volume", "volumes-from", "workdir", "pid", "ipc", "cgroupns", "isolation", "memory-swap"), stopAtPos: true}

var dockerExecSpec = optSpec{shortArg: "euw", longArg: set("env", "env-file", "user", "workdir", "detach-keys"), stopAtPos: true}

func dockerCmd(c *classifier, name string, args []arg, ctx callCtx) flow {
	c.verb(action.VerbExecute)
	words := []string{}
	for _, a := range args {
		if a.lit && !strings.HasPrefix(a.val, "-") {
			words = append(words, strings.ToLower(a.val))
		}
	}
	key := strings.Join(words[:min(2, len(words))], " ")
	all := hasLit(args, "-a", "--all", "--volumes")
	if (key == "system prune" && all) || key == "volume prune" || key == "volume rm" {
		c.verb(action.VerbDelete)
		c.destructive(name+" "+key, "infra", ScopeOutside, "")
	}
	if hasLit(args, "--privileged") || hasLit(args, "--pid=host") {
		c.res.Privilege = true
		c.op("privilege")
	}
	// run/exec/create: the command inside the container is classified.
	g := parseOpts(args, optSpec{shortArg: "cHl", longArg: set("context", "host", "log-level", "config"), stopAtPos: true}).operands()
	if len(g) > 0 && g[0].lit && strings.ToLower(g[0].val) == "container" {
		g = g[1:]
	}
	if len(g) == 0 || !g[0].lit {
		return flow{}
	}
	var p parsed
	switch strings.ToLower(g[0].val) {
	case "run", "create":
		p = parseOpts(g[1:], dockerRunSpec)
		if e, ok := p.val("--entrypoint"); ok {
			c.command(append([]arg{e}, p.operands()[min(1, len(p.operands())):]...), callCtx{in: ctx.in, vars: map[string]arg{}})
			return flow{}
		}
	case "exec":
		p = parseOpts(g[1:], dockerExecSpec)
	default:
		return flow{}
	}
	if ops := p.operands(); len(ops) > 1 {
		return c.command(ops[1:], callCtx{in: ctx.in, vars: map[string]arg{}})
	}
	return flow{}
}
