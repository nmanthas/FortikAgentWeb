// Command fortik runs the Fortik control plane (Decide API + Postgres proxy)
// and operator utilities.
//
//	fortik serve   -config fortik.yaml        run API and/or pgproxy (per config)
//	fortik migrate -config fortik.yaml        apply schema migrations
//	fortik agent register|set-level|list ...  agent registry (operator)
//	fortik diary verify|export|seal ...       Agent Diary integrity tools
//	fortik token hash                          sha256 of a token read from stdin
//	fortik keygen                              new base64 Ed25519 seed for diary signing
package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/access"
	"fortik/internal/agentgw"
	"fortik/internal/alerts"
	"fortik/internal/api"
	"fortik/internal/approvals"
	"fortik/internal/auth"
	"fortik/internal/authz"
	"fortik/internal/baseline"
	"fortik/internal/broker"
	brokeraws "fortik/internal/broker/aws"
	ghbroker "fortik/internal/broker/github"
	"fortik/internal/broker/pgroles"
	"fortik/internal/commap"
	"fortik/internal/config"
	"fortik/internal/console"
	"fortik/internal/containment"
	"fortik/internal/control"
	"fortik/internal/decide"
	"fortik/internal/delegation"
	"fortik/internal/diary"
	"fortik/internal/events"
	"fortik/internal/gateway"
	ghgw "fortik/internal/gateway/github"
	"fortik/internal/gateway/google"
	"fortik/internal/hook"
	"fortik/internal/httpx"
	"fortik/internal/integrations"
	"fortik/internal/memory"
	"fortik/internal/metrics"
	"fortik/internal/overrides"
	"fortik/internal/pgproxy"
	"fortik/internal/policy"
	"fortik/internal/population"
	"fortik/internal/queues"
	"fortik/internal/retention"
	"fortik/internal/secrets"
	"fortik/internal/shadow"
	"fortik/internal/shadow/discoverers"
	"fortik/internal/store"
	"fortik/internal/swarm"
	"fortik/internal/undo"
	"fortik/internal/undo/pgundo"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var err error
	switch os.Args[1] {
	case "serve":
		err = cmdServe(ctx, os.Args[2:])
	case "migrate":
		err = cmdMigrate(ctx, os.Args[2:])
	case "agent":
		err = cmdAgent(ctx, os.Args[2:])
	case "diary":
		err = cmdDiary(ctx, os.Args[2:])
	case "token":
		err = cmdToken(os.Args[2:])
	case "secrets":
		err = cmdSecrets(ctx, os.Args[2:])
	case "access":
		err = cmdAccess(ctx, os.Args[2:])
	case "integration":
		err = cmdIntegration(ctx, os.Args[2:])
	case "hook":
		if len(os.Args) < 3 || os.Args[2] != "claude-code" {
			err = errors.New("hook: want 'claude-code' (reads the PreToolUse event on stdin)")
		} else {
			os.Exit(hook.RunClaudeCode(os.Stdin, os.Stdout, os.Stderr, os.Getenv))
		}
	case "agentgw":
		if len(os.Args) < 3 || os.Args[2] != "config" {
			err = errors.New("agentgw: want 'config' (-spec routes.yaml [-out f] [-fortik-snippet] | -lint file)")
		} else {
			err = agentgw.RunConfigCommand(os.Args[3:], os.Stdout, os.Stderr)
		}
	case "keygen":
		seed := make([]byte, ed25519.SeedSize)
		if _, err = rand.Read(seed); err == nil {
			fmt.Println(base64.StdEncoding.EncodeToString(seed))
		}
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "fortik:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: fortik <serve|migrate|agent|diary|token|keygen> [flags]
  serve   -config fortik.yaml [-migrate]
  migrate -config fortik.yaml
  agent   register  -config f -id ID [-name N -type T -platform P -sponsor S -team B -copy-cap N]
  agent   set-level -config f -id ID -level LEVEL -reason TEXT [-actor NAME]
  agent   list      -config f
  diary   verify    -config f
  diary   export    -config f [-agent ID] [-from RFC3339] [-to RFC3339] [-out FILE]
  diary   seal      -config f -day YYYY-MM-DD
  token   hash      (reads the token on stdin, prints its sha256)
  secrets put       -config f -name NAME [-if-absent] (value on stdin; writable providers only)
  access  set       -config f -id ID -system S -profile JSON -reason TEXT
  integration put   -config f -key KEY -config-json JSON [-secrets-stdin | -secrets-json JSON]
  keygen            (prints a new base64 Ed25519 seed)`)
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	_ = l.UnmarshalText([]byte(level))
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}

type deps struct {
	cfg    *config.Config
	log    *slog.Logger
	pool   *pgxpool.Pool
	sec    secrets.Provider
	diary  *diary.Diary
	ctl    *control.Store
	signer *diary.Signer
}

func load(ctx context.Context, path string) (*deps, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	log := newLogger(cfg.LogLevel)
	sec, err := secrets.Open(cfg.Secrets)
	if err != nil {
		return nil, err
	}
	pool, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	d := diary.New(pool)
	dp := &deps{cfg: cfg, log: log, pool: pool, sec: sec, diary: d, ctl: control.NewStore(pool, d)}
	if raw, err := sec.Get(ctx, cfg.Diary.SigningKeySecret); err == nil {
		if dp.signer, err = diary.NewSigner(raw); err != nil {
			return nil, err
		}
		pub, _ := base64.StdEncoding.DecodeString(dp.signer.PublicKey())
		d.TrustRootKeys(ed25519.PublicKey(pub))
		// Unknown-token refs in shadow findings are keyed from the same
		// server secret (a derived key; never the signing key itself).
		shadow.SetTokenRefKey(raw)
	} else if !errors.Is(err, secrets.ErrNotFound) {
		return nil, err
	}
	for _, k := range cfg.Diary.RetiredPublicKeys {
		pub, err := base64.StdEncoding.DecodeString(k)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("config: diary.retired_public_keys: %q is not a base64 Ed25519 public key", k)
		}
		d.TrustRootKeys(ed25519.PublicKey(pub))
	}
	return dp, nil
}

func cmdServe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("config", "fortik.yaml", "config file")
	migrate := fs.Bool("migrate", false, "apply migrations before serving")
	_ = fs.Parse(args)
	dp, err := load(ctx, *cfgPath)
	if err != nil {
		return err
	}
	defer dp.pool.Close()
	cfg, log := dp.cfg, dp.log
	if *migrate {
		applied, err := store.Migrate(ctx, dp.pool)
		if err != nil {
			return err
		}
		log.Info("migrations applied", "versions", applied)
	}
	if !cfg.API.Enabled && !cfg.PGProxy.Enabled && !cfg.Gateway.Enabled {
		return errors.New("nothing to serve: enable api, pgproxy and/or gateway in the config")
	}
	if dp.signer == nil {
		log.Warn("no diary signing key configured: /v1/diary/export and seal are unavailable", "secret", cfg.Diary.SigningKeySecret)
	}
	store := secrets.AsStore(dp.sec)
	if !secrets.Writable(dp.sec) {
		log.Warn("secret provider is read-only: integrations and agent tokens cannot be saved from the console", "provider", cfg.Secrets.Provider)
	}

	// --- policy -----------------------------------------------------------
	eng, err := policy.NewEngine(ctx, cfg.Policy.Dir, log)
	if err != nil {
		return err
	}
	eng.OnReload = func(version string, rerr error) {
		ev := diary.Event{EventType: diary.EventPolicyReloaded, Actor: "system:policy", Data: map[string]any{"version": version, "dir": cfg.Policy.Dir}}
		outcome := "ok"
		if rerr != nil {
			ev.EventType, outcome = diary.EventPolicyReloadFail, "failed"
			ev.Data["error"] = rerr.Error()
		}
		metrics.PolicyReloads.WithLabelValues(outcome).Inc()
		if _, err := dp.diary.Append(context.Background(), ev); err != nil {
			log.Error("diary append failed", "err", err)
		}
	}
	if _, err := dp.diary.Append(ctx, diary.Event{EventType: diary.EventPolicyReloaded, Actor: "system:policy",
		Data: map[string]any{"version": eng.Version(), "dir": cfg.Policy.Dir, "startup": true}}); err != nil {
		return fmt.Errorf("record policy version in diary: %w", err)
	}
	if cfg.Policy.HotReload {
		go eng.Watch(ctx, cfg.Policy.PollEvery)
	}
	log.Info("policy bundle loaded", "version", eng.Version(), "dir", cfg.Policy.Dir)

	// --- core: access profiles, decide, undo, integrations -------------------
	accStore := access.NewPGStore(dp.pool, dp.diary)
	svc := &decide.Service{Pool: dp.pool, Policy: eng, Control: dp.ctl, Diary: dp.diary, Fail: cfg.Fail, Log: log,
		Access: accStore, YellowHoldsThreshold: cfg.Ladder.YellowHoldsThreshold, YellowWindow: cfg.Ladder.YellowWindow}
	us := undo.NewPGStore(dp.pool, dp.diary)
	intStore := integrations.NewPGStore(dp.pool, dp.diary, store)
	testers := integrations.NewRegistry()

	// --- broker and adapters ---------------------------------------------------
	// Several adapters record issuances through the broker, which in turn needs
	// the adapter map at construction: a late-bound recorder breaks the cycle
	// (issuances are refused until it is set, a few lines below).
	late := &pgroles.LateRecorder{}
	roles, err := pgroles.New(pgroles.Config{Integrations: intStore, Access: accStore, Control: dp.ctl, Recorder: late,
		TTL: cfg.Broker.PostgresSessionTTL, Log: log.With("component", "pgroles")})
	if err != nil {
		return err
	}
	ghClient := ghbroker.NewClient(nil)
	ghBrk, err := ghbroker.NewAdapter(ghbroker.AdapterConfig{Client: ghClient, Source: intStore, Profiles: accStore, Log: log.With("component", "github")})
	if err != nil {
		return err
	}
	defer ghBrk.Close()
	ghGW, err := ghgw.New(ghgw.Config{Source: intStore, Profiles: accStore, Undo: us, Recorder: late, Client: ghClient, Log: log.With("component", "github")})
	if err != nil {
		return err
	}
	ghBrk.OnRevokeAgent(ghGW.DropAgent)
	gad, err := google.New(google.Options{Config: cfg.Gateway, Source: intStore, Directory: google.PGDirectory{Pool: dp.pool},
		Pool: dp.pool, Diary: dp.diary, Secrets: store, Issuances: late, Log: log.With("component", "google")})
	if err != nil {
		return err
	}
	adapters := map[string]broker.Adapter{
		"aws":      brokeraws.New(intStore, cfg.Broker.AWSSessionTTL, log.With("component", "aws")),
		"github":   ghBrk,
		"postgres": roles,
		// Agents never hold memory-store credentials; registered so the
		// revocation result says so explicitly.
		memory.System: memory.CredentialAdapter{},
	}
	for k, a := range gad.BrokerAdapters() {
		adapters[k] = a
	}
	brk := broker.New(svc, dp.pool, dp.diary, accStore, adapters, log.With("component", "broker"))
	late.Set(brk)
	for _, t := range []integrations.Tester{brokeraws.NewTester(), ghbroker.NewTester(ghClient), roles, google.NewTester(cfg.Gateway, nil), memory.Tester{}} {
		if err := testers.Register(t); err != nil {
			return err
		}
	}

	errc := make(chan error, 8)

	// --- Phase 3: alerts, delegation chains, population, suspensions, approvals ----
	alertStore := alerts.NewPGStore(dp.pool, dp.diary)
	delegStore, err := delegation.NewPGStore(ctx, dp.pool, dp.diary, store, cfg.Delegation, delegation.WithLogger(log.With("component", "delegation")))
	if err != nil {
		return err
	}
	delegObs, err := delegation.NewObserver(delegStore, dp.ctl, dp.diary, alertStore, cfg.Delegation.BypassOriginLevel)
	if err != nil {
		return err
	}
	counters, closeCounters, err := population.NewCounters(ctx, cfg.Counters)
	if err != nil {
		return err
	}
	defer closeCounters() //nolint:errcheck
	pop, err := population.New(dp.pool, dp.diary, alertStore, counters, cfg.Population, log.With("component", "population"))
	if err != nil {
		return err
	}
	revokers := map[string]overrides.Revoker{}
	for k, a := range adapters {
		revokers[k] = a
	}
	ovStore := overrides.NewPGStore(dp.pool, dp.diary, revokers, log.With("component", "overrides"))
	ovWorker, err := overrides.NewWorker(ovStore, accStore, alertStore, cfg.Overrides.SweepInterval, log.With("component", "overrides"))
	if err != nil {
		return err
	}
	apprSvc := approvals.New(dp.pool, dp.diary, us, intStore, approvals.Config{
		GrantTTL: cfg.Approvals.GrantTTL, AllowOwnerApproval: cfg.Approvals.AllowOwnerApproval, TrashRetention: cfg.Undo.TrashRetention,
		AllowTokenPairs: cfg.Approvals.AllowTokenPairs,
	}, log.With("component", "approvals"))
	if cfg.Approvals.AllowTokenPairs {
		log.Warn("approvals.allow_token_pairs is on: two API tokens can supply both votes of a two-person rule (dev/demo only)")
	}
	// --- Phase 4: memory protection, queue control, containment, retention ----
	memStores := memory.NewStores(intStore, cfg.Memory.PromotionDelay, log.With("component", "memory"))
	defer memStores.Close()
	memSvc, err := memory.NewService(dp.pool, dp.diary, memStores, cfg.Memory, log.With("component", "memory"))
	if err != nil {
		return err
	}
	qs := queues.New(intStore, log.With("component", "queues"))
	// Celery holds are one-shot per pause: re-hold new messages of agents
	// that stay suspended or quarantined.
	go queues.NewHoldWorker(dp.pool, qs.Celery, 10*time.Second, log.With("component", "queues")).Run(ctx)
	if err := qs.RegisterTesters(testers); err != nil {
		return err
	}
	contain, err := containment.New(dp.pool, dp.diary, dp.ctl, brk, qs.Adapters(), memSvc, pop.InstanceControl(), log.With("component", "containment"))
	if err != nil {
		return err
	}
	retW := retention.New(dp.pool, dp.diary, intStore, cfg.Undo, cfg.Retention, cfg.Memory, log.With("component", "retention"),
		retention.WithSnapshotPurger(memory.NewSnapshotPurger(memStores)))
	go retW.Run(ctx)
	go memory.NewPromotionWorker(memSvc, cfg.Memory.PromotionPoll, log.With("component", "memory")).Run(ctx)
	go memory.NewSnapshotWorker(memSvc, cfg.Memory.SnapshotEvery, log.With("component", "memory")).Run(ctx)

	// --- Phase 5: swarms, baselines, shadow agents, communication map --------
	swarmSvc, err := swarm.New(dp.pool, dp.diary, alertStore, contain, cfg.Swarm, swarm.Options{
		HeldTTL: svc.HeldTTL, StaleAfter: cfg.Population.StaleAfter, Signer: dp.signer, AllowTokenPairs: cfg.Approvals.AllowTokenPairs,
		Log: log.With("component", "swarm")})
	if err != nil {
		return err
	}
	go swarmSvc.Run(ctx) // spawn-tree, copy-surge and converging-target sweep
	bParams := baseline.ParamsFrom(cfg.Baseline)
	bStore, err := baseline.NewStore(ctx, cfg.Counters, bParams)
	if err != nil {
		return err
	}
	defer bStore.Close() //nolint:errcheck
	baseSvc := baseline.New(dp.pool, bStore, bParams, baseline.Options{}, log.With("component", "baseline"))
	if _, err := baseSvc.Backfill(ctx); err != nil { // before any decision is served
		return fmt.Errorf("baseline backfill: %w", err)
	}
	go baseSvc.Run(ctx)
	shadowDisc, err := discoverers.New(discoverers.Config{Integrations: intStore, GitHub: ghClient,
		GoogleTokenURL: cfg.Gateway.GoogleTokenURL, PostgresExcludeRoles: cfg.Shadow.PostgresExcludeRoles,
		GitHubKnownApps: cfg.Shadow.GitHubKnownApps, Log: log.With("component", "shadow")})
	if err != nil {
		return err
	}
	shadowSvc, err := shadow.NewService(shadow.Config{Pool: dp.pool, Diary: dp.diary, Alerts: alertStore, Discoverers: shadowDisc,
		Log: log.With("component", "shadow")})
	if err != nil {
		return err
	}
	go shadowSvc.Run(ctx, cfg.Shadow.SweepInterval)
	shadowRec, err := shadow.NewRecorder(shadow.RecorderConfig{Pool: dp.pool, Diary: dp.diary, Alerts: alertStore, Log: log.With("component", "shadow")})
	if err != nil {
		return err
	}
	go shadowRec.Run(ctx)
	mapWorker, err := commap.NewWorker(dp.pool, dp.diary, alertStore, cfg.Map, log.With("component", "commap"), commap.Options{})
	if err != nil {
		return err
	}
	go mapWorker.Run(ctx) // 5-minute edge rollup, hidden signals, retention
	mapSvc, err := commap.NewService(dp.pool, cfg.Map, commap.Limits{})
	if err != nil {
		return err
	}

	// Enrichers: population last (its Enrich spends rate budget, so an earlier
	// failure must not count against the agent). Observers share one tx: the
	// swarm observer first (it may turn an allow into a breaker hold that the
	// others must see), the baseline observer last (count only what commits).
	svc.Enrichers = []decide.Enricher{delegation.NewEnricher(delegStore), overrides.NewEnricher(ovStore), approvals.NewGrantEnricher(dp.pool),
		memory.NewEnricher(memSvc), swarmSvc, baseSvc, shadow.NewEnricher(dp.pool), commap.NewEnricher(cfg.Map.EncodedParamMin), pop}
	svc.Observers = []decide.Observer{swarmSvc, delegObs, approvals.NewGrantObserver(dp.diary), pop, baseSvc}
	go delegStore.RunExpiry(ctx, 30*time.Second)
	go ovWorker.Run(ctx)
	go apprSvc.ExpiryWorker(30 * time.Second).Run(ctx)
	if cfg.AgentGW.Enabled {
		verbs, err := agentgw.LoadToolVerbs(cfg.Policy.Dir)
		if err != nil {
			return err
		}
		cb, err := agentgw.New(cfg.AgentGW, svc, gateway.NewAgentAuth(dp.sec, cfg.PGProxy.AgentTokensSecret, log), delegStore, verbs,
			log.With("component", "agentgw"), agentgw.WithDiary(dp.diary), agentgw.WithPool(dp.pool))
		if err != nil {
			return err
		}
		go func() {
			log.Info("agentgateway callout listening", "addr", cfg.AgentGW.Listen)
			if err := cb.ListenAndServe(ctx); err != nil && ctx.Err() == nil {
				errc <- fmt.Errorf("agentgw callout: %w", err)
			}
		}()
	}

	// --- undo executors -----------------------------------------------------------
	executors := map[string]undo.Executor{}
	for _, ex := range []undo.Executor{pgundo.NewExecutor(cfg.PGProxy, dp.sec, pgundo.WithIntegrations(intStore)), gad.UndoExecutor(), ghGW.UndoExecutor(),
		memory.NewUndoExecutor(memStores)} {
		for _, k := range ex.Kinds() {
			executors[k] = ex
		}
	}

	serveHTTP := func(name, addr string, h http.Handler) {
		hs := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout: 60 * time.Second, WriteTimeout: 3 * time.Minute, IdleTimeout: 2 * time.Minute}
		go func() {
			log.Info(name+" listening", "addr", addr)
			if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("%s: %w", name, err)
			}
		}()
		go func() {
			<-ctx.Done()
			sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = hs.Shutdown(sctx)
		}()
	}

	if cfg.PGProxy.Enabled {
		px, err := pgproxy.New(cfg.PGProxy, cfg.Undo, dp.sec, svc, us, log.With("component", "pgproxy"), pgproxy.WithRoles(roles),
			pgproxy.WithShadow(shadowRec))
		if err != nil {
			return err
		}
		go func() {
			log.Info("pgproxy listening", "addr", cfg.PGProxy.Listen, "yaml_upstreams", len(cfg.PGProxy.Upstreams))
			errc <- px.ListenAndServe(ctx)
		}()
	}

	if cfg.Gateway.Enabled {
		memGW, err := memory.NewGatewayAdapter(memSvc, us, cfg.Undo.SnapshotRetention, log.With("component", "memory"))
		if err != nil {
			return err
		}
		gw, err := gateway.NewServer(cfg.Gateway, svc, gateway.NewAgentAuth(dp.sec, cfg.PGProxy.AgentTokensSecret, log),
			[]gateway.Adapter{gad, ghGW, memGW}, log.With("component", "gateway"), gateway.WithDiary(dp.diary), gateway.WithShadow(shadowRec))
		if err != nil {
			return err
		}
		issue := http.NewServeMux()
		broker.NewHandler(brk, log).Register(issue)
		gw.Mount("POST /v1/credentials/issue", issue.ServeHTTP)
		population.NewGatewayHandler(pop, svc, log).Mount(gw) // /v1/instances/register|heartbeat|stop
		hookVerbs, err := agentgw.LoadToolVerbs(cfg.Policy.Dir)
		if err != nil {
			return err
		}
		hh, err := hook.NewHandler(cfg.Hook, svc, hookVerbs, log.With("component", "hook"), hook.WithInternalHosts(cfg.AgentGW.InternalHosts),
			hook.WithShadow(shadowRec))
		if err != nil {
			return err
		}
		gw.Mount(hook.Route, hh.ServeHTTP) // Claude Code PreToolUse decisions
		go gad.NewDelayedSender().Run(ctx)
		serveHTTP("gateway", cfg.Gateway.Listen, gw)
	}

	if cfg.API.Enabled {
		tokAuth, err := api.NewTokenAuth(ctx, dp.sec, cfg.API.TokensSecret)
		if err != nil {
			return err
		}
		authSvc, err := auth.New(auth.Options{Config: cfg.Auth, APIListen: cfg.API.Listen, Pool: dp.pool, Diary: dp.diary,
			Secrets: dp.sec, Log: log.With("component", "auth")})
		if err != nil {
			return err
		}
		bus, err := events.New(ctx, cfg.Events, log)
		if err != nil {
			return err
		}
		defer bus.Close()
		tailer := events.NewTailer(dp.diary, bus, log.With("component", "events"))
		go func() {
			if err := tailer.Run(ctx); err != nil && ctx.Err() == nil {
				log.Error("diary tailer stopped", "err", err)
			}
		}()

		srv := api.NewServer(api.Server{Pool: dp.pool, Decider: svc, Diary: dp.diary, Signer: dp.signer, Undo: us,
			Executors: executors, Policy: eng, Log: log.With("component", "api"),
			Sessions: authSvc, Revoker: contain, Secrets: store, AgentTokensSecret: cfg.PGProxy.AgentTokensSecret,
			LoopbackHosts: httpx.IsLoopbackName(cfg.API.Listen), AllowedHosts: cfg.API.AllowedHosts, AgentGuard: pop}, tokAuth)
		if !httpx.IsLoopbackName(cfg.API.Listen) && len(cfg.API.AllowedHosts) == 0 {
			log.Warn("api.allowed_hosts is empty on a non-loopback listener: any Host header is accepted (DNS rebinding)")
		}
		srv.Mount(authSvc.Routes)
		srv.Mount(access.NewHandler(accStore, dp.pool, log).Register)
		srv.Mount(integrations.NewHandler(intStore, testers, log).Register)
		sse := events.NewSSE(bus, events.SSEOptions{Head: tailer.Head, Backfill: tailer.Backfill, Log: log,
			Revalidate: func(r *http.Request) error { return srv.Reauthorize(r, authz.RoleAuditor) }})
		srv.Mount(sse.Mount)
		srv.Mount(alerts.NewHandler(alertStore, log).Register)
		srv.Mount(delegation.NewHandler(delegStore, log).Register)
		srv.Mount(population.NewAPIHandler(pop, log).Register)
		srv.Mount(overrides.NewHandler(ovStore, log).Register)
		srv.Mount(approvals.NewHandler(apprSvc).Register)
		srv.Mount(containment.NewHandler(contain, log.With("component", "containment")).Register)
		srv.Mount(memory.NewHandler(memSvc, log.With("component", "memory")).Register)
		srv.Mount(swarm.NewHandler(swarmSvc, log.With("component", "swarm")).Register)
		srv.Mount(baseline.NewHandler(baseSvc).Register)
		srv.Mount(shadow.NewHandler(shadowSvc, log.With("component", "shadow")).Register)
		mapLive := commap.NewLive(bus, events.SSEOptions{Head: tailer.Head, Backfill: tailer.Backfill, Log: log,
			Revalidate: func(r *http.Request) error { return srv.Reauthorize(r, authz.RoleAuditor, authz.RoleSecurity) }}, mapSvc)
		srv.Mount(commap.NewHandler(mapSvc, mapLive, log.With("component", "commap")).Register)
		if cfg.Console.Enabled {
			srv.Mount(func(mux *http.ServeMux) { mux.Handle("/", console.Handler()) }) // last: least specific
		}
		serveHTTP("api", cfg.API.Listen, srv.Handler())
	}

	select {
	case <-ctx.Done():
		log.Info("shutting down")
		time.Sleep(200 * time.Millisecond)
		return nil
	case err := <-errc:
		return err
	}
}

func cmdMigrate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("migrate", flag.ExitOnError)
	cfgPath := fs.String("config", "fortik.yaml", "config file")
	_ = fs.Parse(args)
	dp, err := load(ctx, *cfgPath)
	if err != nil {
		return err
	}
	defer dp.pool.Close()
	applied, err := store.Migrate(ctx, dp.pool)
	if err != nil {
		return err
	}
	fmt.Printf("applied %d migration(s): %v\n", len(applied), applied)
	return nil
}

func cmdAgent(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return errors.New("agent: want register|set-level|list")
	}
	fs := flag.NewFlagSet("agent "+args[0], flag.ExitOnError)
	cfgPath := fs.String("config", "fortik.yaml", "config file")
	id := fs.String("id", "", "agent id")
	name := fs.String("name", "", "display name")
	typ := fs.String("type", "", "agent type (e.g. claude_code, langgraph)")
	platform := fs.String("platform", "", "platform")
	sponsor := fs.String("sponsor", "", "human sponsor (email)")
	team := fs.String("team", "", "business unit")
	copyCap := fs.Int("copy-cap", 1, "max running copies")
	lvl := fs.String("level", "", "control level (FULL..KILLED)")
	reason := fs.String("reason", "", "reason (required for set-level)")
	actor := fs.String("actor", "", "operator name recorded in the Diary")
	_ = fs.Parse(args[1:])
	dp, err := load(ctx, *cfgPath)
	if err != nil {
		return err
	}
	defer dp.pool.Close()
	who := "cli:" + firstNonEmpty(*actor, os.Getenv("USER"), "operator")
	switch args[0] {
	case "register":
		if *id == "" {
			return errors.New("-id is required")
		}
		inserted, err := dp.ctl.Register(ctx, control.Agent{AgentID: *id, Name: *name, Type: *typ, Platform: *platform,
			Sponsor: *sponsor, BusinessUnit: *team, CopyCap: *copyCap}, who)
		if err != nil {
			return err
		}
		fmt.Printf("agent %s registered (new=%v)\n", *id, inserted)
	case "set-level":
		to, err := control.ParseLevel(*lvl)
		if err != nil {
			return err
		}
		from, err := dp.ctl.SetLevel(ctx, *id, to, *reason, who)
		if err != nil {
			return err
		}
		fmt.Printf("agent %s: %s -> %s\n", *id, from, to)
	case "list":
		rows, err := dp.pool.Query(ctx, `SELECT agent_id, level, type, sponsor FROM agents ORDER BY agent_id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var aid, t, s string
			var l int16
			if err := rows.Scan(&aid, &l, &t, &s); err != nil {
				return err
			}
			fmt.Printf("%-28s %-12s %-14s %s\n", aid, control.Level(l), t, s)
		}
		return rows.Err()
	default:
		return fmt.Errorf("agent: unknown subcommand %q", args[0])
	}
	return nil
}

func cmdDiary(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return errors.New("diary: want verify|export|seal")
	}
	fs := flag.NewFlagSet("diary "+args[0], flag.ExitOnError)
	cfgPath := fs.String("config", "fortik.yaml", "config file")
	agent := fs.String("agent", "", "agent filter (export)")
	from := fs.String("from", "", "RFC3339 lower bound (export)")
	to := fs.String("to", "", "RFC3339 upper bound (export)")
	out := fs.String("out", "", "output file (export; default stdout)")
	day := fs.String("day", "", "UTC day to seal, YYYY-MM-DD")
	_ = fs.Parse(args[1:])
	dp, err := load(ctx, *cfgPath)
	if err != nil {
		return err
	}
	defer dp.pool.Close()
	who := "cli:" + firstNonEmpty(os.Getenv("USER"), "operator")
	switch args[0] {
	case "verify":
		rep, err := dp.diary.VerifyChain(ctx)
		if err != nil {
			return err
		}
		b, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(b))
		if !rep.OK {
			return errors.New("diary chain verification FAILED")
		}
	case "export":
		f := diary.Filter{AgentID: *agent, Limit: 10000}
		if *from != "" {
			if f.From, err = time.Parse(time.RFC3339, *from); err != nil {
				return err
			}
		}
		if *to != "" {
			if f.To, err = time.Parse(time.RFC3339, *to); err != nil {
				return err
			}
		}
		exp, err := dp.diary.Export(ctx, f, dp.signer, who)
		if err != nil {
			return err
		}
		b, _ := json.MarshalIndent(exp, "", "  ")
		if *out == "" {
			fmt.Println(string(b))
			return nil
		}
		return os.WriteFile(*out, b, 0o600)
	case "seal":
		d, err := time.Parse(time.DateOnly, *day)
		if err != nil {
			return fmt.Errorf("-day: %w", err)
		}
		root, err := dp.diary.SealDay(ctx, d, dp.signer, who)
		if err != nil {
			return err
		}
		b, _ := json.MarshalIndent(root, "", "  ")
		fmt.Println(string(b))
	default:
		return fmt.Errorf("diary: unknown subcommand %q", args[0])
	}
	return nil
}

func cmdToken(args []string) error {
	if len(args) != 1 || args[0] != "hash" {
		return errors.New("token: want 'hash' (token on stdin)")
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return errors.New("no token on stdin")
	}
	sum := sha256.Sum256([]byte(strings.TrimRight(line, "\r\n")))
	fmt.Println(hex.EncodeToString(sum[:]))
	return nil
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func cmdSecrets(ctx context.Context, args []string) error {
	if len(args) >= 1 && args[0] == "merge-json" {
		return cmdSecretsMergeJSON(ctx, args[1:])
	}
	if len(args) < 1 || args[0] != "put" {
		return errors.New("secrets: want 'put' or 'merge-json'")
	}
	fs := flag.NewFlagSet("secrets put", flag.ExitOnError)
	cfgPath := fs.String("config", "fortik.yaml", "config file")
	name := fs.String("name", "", "secret name")
	ifAbsent := fs.Bool("if-absent", false, "only write when the secret does not exist yet (never overwrite a managed value)")
	_ = fs.Parse(args[1:])
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	sec, err := secrets.Open(cfg.Secrets)
	if err != nil {
		return err
	}
	st, ok := sec.(secrets.Store)
	if !ok {
		return fmt.Errorf("secret provider %q is read-only", cfg.Secrets.Provider)
	}
	val, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	if err != nil {
		return err
	}
	val = []byte(strings.TrimRight(string(val), "\r\n"))
	if *name == "" || len(val) == 0 {
		return errors.New("-name and a non-empty value on stdin are required")
	}
	if *ifAbsent {
		_, err := st.Get(ctx, *name)
		switch {
		case err == nil:
			fmt.Fprintf(os.Stderr, "secret %s already exists; left unchanged\n", *name)
			return nil
		case !errors.Is(err, secrets.ErrNotFound):
			return fmt.Errorf("check %s: %w", *name, err)
		}
	}
	return st.Put(ctx, *name, val)
}

func cmdAccess(ctx context.Context, args []string) error {
	if len(args) < 1 || args[0] != "set" {
		return errors.New("access: want 'set'")
	}
	fs := flag.NewFlagSet("access set", flag.ExitOnError)
	cfgPath := fs.String("config", "fortik.yaml", "config file")
	id := fs.String("id", "", "agent id")
	system := fs.String("system", "", "gmail|drive|github|aws|postgres")
	profile := fs.String("profile", "", "profile JSON")
	reason := fs.String("reason", "", "reason")
	_ = fs.Parse(args[1:])
	dp, err := load(ctx, *cfgPath)
	if err != nil {
		return err
	}
	defer dp.pool.Close()
	p, err := access.NewPGStore(dp.pool, dp.diary).Put(ctx, *id, *system, json.RawMessage(*profile),
		"cli:"+firstNonEmpty(os.Getenv("USER"), "operator"), *reason)
	if err != nil {
		return err
	}
	fmt.Printf("access %s/%s -> version %d\n", *id, *system, p.Version)
	return nil
}

func cmdIntegration(ctx context.Context, args []string) error {
	if len(args) < 1 || args[0] != "put" {
		return errors.New("integration: want 'put'")
	}
	fs := flag.NewFlagSet("integration put", flag.ExitOnError)
	cfgPath := fs.String("config", "fortik.yaml", "config file")
	key := fs.String("key", "", "integration key (google_workspace|github|aws|postgres:<name>)")
	cfgJSON := fs.String("config-json", "{}", "non-secret settings JSON")
	secJSON := fs.String("secrets-json", "{}", "secret fields JSON (prefer the console; visible in ps, use -secrets-stdin)")
	secStdin := fs.Bool("secrets-stdin", false, "read the secret fields JSON from stdin instead of -secrets-json")
	_ = fs.Parse(args[1:])
	if *secStdin {
		b, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
		if err != nil {
			return err
		}
		*secJSON = string(b)
	}
	dp, err := load(ctx, *cfgPath)
	if err != nil {
		return err
	}
	defer dp.pool.Close()
	var in integrations.ConfigureInput
	if err := json.Unmarshal([]byte(*cfgJSON), &in.Config); err != nil {
		return fmt.Errorf("-config-json: %w", err)
	}
	if err := json.Unmarshal([]byte(*secJSON), &in.Secrets); err != nil {
		return fmt.Errorf("-secrets-json: %w", err)
	}
	st := integrations.NewPGStore(dp.pool, dp.diary, secrets.AsStore(dp.sec))
	got, err := st.Configure(ctx, *key, in, "cli:"+firstNonEmpty(os.Getenv("USER"), "operator"))
	if err != nil {
		return err
	}
	fmt.Printf("integration %s configured (status %s)\n", got.Key, got.Status)
	return nil
}

// cmdSecretsMergeJSON adds keys from a JSON object on stdin to a JSON-object
// secret, never overwriting existing keys (dev seeding must not clobber tokens
// issued from the console).
func cmdSecretsMergeJSON(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("secrets merge-json", flag.ExitOnError)
	cfgPath := fs.String("config", "fortik.yaml", "config file")
	name := fs.String("name", "", "secret name")
	_ = fs.Parse(args)
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	sec, err := secrets.Open(cfg.Secrets)
	if err != nil {
		return err
	}
	st, ok := sec.(secrets.Store)
	if !ok {
		return fmt.Errorf("secret provider %q is read-only", cfg.Secrets.Provider)
	}
	var add map[string]any
	if err := json.NewDecoder(io.LimitReader(os.Stdin, 1<<20)).Decode(&add); err != nil {
		return fmt.Errorf("stdin: %w", err)
	}
	cur := map[string]any{}
	if raw, err := st.Get(ctx, *name); err == nil {
		if err := json.Unmarshal(raw, &cur); err != nil {
			return fmt.Errorf("existing secret %s is not a JSON object", *name)
		}
	} else if !errors.Is(err, secrets.ErrNotFound) {
		return err
	}
	added := 0
	for k, v := range add {
		if _, exists := cur[k]; !exists {
			cur[k] = v
			added++
		}
	}
	if added == 0 {
		return nil
	}
	b, err := json.Marshal(cur)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "secret %s: added %d key(s)\n", *name, added)
	return st.Put(ctx, *name, b)
}
