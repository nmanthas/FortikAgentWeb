package integrations

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"fortik/internal/authz"
	"fortik/internal/httpx"
	"fortik/internal/secrets"
)

// TestTimeout bounds one live connection test.
const TestTimeout = 15 * time.Second

const maxConfigureBody = 256 << 10

// Handler serves the Integrations API. The caller's principal must already
// be in the request context (authz.With, set by the API's auth middleware,
// which also enforces CSRF for cookie sessions).
type Handler struct {
	store       *PGStore
	testers     *Registry
	log         *slog.Logger
	testTimeout time.Duration
}

// NewHandler builds the handler. testers may be empty: tests then answer 501.
func NewHandler(store *PGStore, testers *Registry, log *slog.Logger) *Handler {
	if testers == nil {
		testers = NewRegistry()
	}
	if log == nil {
		log = slog.Default()
	}
	return &Handler{store: store, testers: testers, log: log, testTimeout: TestTimeout}
}

// Register mounts the routes:
//
//	GET    /v1/integrations/schema      auditor|security  field definitions
//	GET    /v1/integrations             auditor|security  configured integrations (secrets as {"set":bool})
//	GET    /v1/integrations/{key}       auditor|security  one integration
//	PUT    /v1/integrations/{key}       security          configure
//	POST   /v1/integrations/{key}/test  security          live connection test
//	DELETE /v1/integrations/{key}       security          delete secrets and settings
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/integrations/schema", h.schema)
	mux.HandleFunc("GET /v1/integrations", h.list)
	mux.HandleFunc("GET /v1/integrations/{key}", h.get)
	mux.HandleFunc("PUT /v1/integrations/{key}", h.configure)
	mux.HandleFunc("POST /v1/integrations/{key}/test", h.test)
	mux.HandleFunc("DELETE /v1/integrations/{key}", h.delete)
}

// SecretState is how a secret field appears in API responses: never a value.
type SecretState struct {
	Set bool `json:"set"`
}

// View is the API representation of an integration.
type View struct {
	Integration
	Secrets       map[string]SecretState `json:"secrets"`
	TestAvailable bool                   `json:"test_available"`
}

func (h *Handler) view(in Integration) View {
	v := View{Integration: in, Secrets: map[string]SecretState{}}
	if schema, ok := SchemaFor(in.System); ok {
		for _, f := range secretFieldNames(schema) {
			v.Secrets[f] = SecretState{Set: slices.Contains(in.SecretFields, f)}
		}
	}
	_, v.TestAvailable = h.testers.Tester(in.System)
	return v
}

func (h *Handler) schema(w http.ResponseWriter, r *http.Request) {
	if _, ok := authz.Require(w, r, authz.RoleAuditor, authz.RoleSecurity); !ok {
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"schemas": Schemas()})
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	if _, ok := authz.Require(w, r, authz.RoleAuditor, authz.RoleSecurity); !ok {
		return
	}
	ins, err := h.store.ListIntegrations(r.Context())
	if err != nil {
		h.internal(w, "list integrations", err)
		return
	}
	out := make([]View, 0, len(ins))
	for _, in := range ins {
		out = append(out, h.view(in))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"integrations": out})
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	if _, ok := authz.Require(w, r, authz.RoleAuditor, authz.RoleSecurity); !ok {
		return
	}
	in, err := h.store.GetIntegration(r.Context(), r.PathValue("key"))
	if err != nil {
		h.fail(w, "get integration", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, h.view(in))
}

func (h *Handler) configure(w http.ResponseWriter, r *http.Request) {
	p, ok := authz.Require(w, r, authz.RoleSecurity)
	if !ok {
		return
	}
	key := r.PathValue("key")
	if _, err := ParseKey(key); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	var body ConfigureInput
	if err := httpx.DecodeStrict(r, &body, maxConfigureBody); err != nil {
		// The decoder's message can quote the offending token; never echo
		// any of it back (it may be part of a secret).
		httpx.WriteError(w, http.StatusBadRequest, `invalid JSON body: want {"config":{...},"secrets":{...}} with known fields only`)
		return
	}
	in, err := h.store.Configure(r.Context(), key, body, p.Actor())
	if err != nil {
		h.fail(w, "configure integration", err)
		return
	}
	h.log.Info("integration configured", "key", key, "actor", p.Actor(), "secret_fields", in.SecretFields)
	httpx.WriteJSON(w, http.StatusOK, h.view(in))
}

func (h *Handler) delete(w http.ResponseWriter, r *http.Request) {
	p, ok := authz.Require(w, r, authz.RoleSecurity)
	if !ok {
		return
	}
	key := r.PathValue("key")
	if err := h.store.Delete(r.Context(), key, p.Actor()); err != nil {
		h.fail(w, "delete integration", err)
		return
	}
	h.log.Info("integration deleted", "key", key, "actor", p.Actor())
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"deleted": key})
}

// TestResponse is the body of POST /v1/integrations/{key}/test.
type TestResponse struct {
	OK          bool   `json:"ok"`
	Error       string `json:"error,omitempty"` // sanitised
	DurationMS  int64  `json:"duration_ms"`
	Integration View   `json:"integration"`
}

func (h *Handler) test(w http.ResponseWriter, r *http.Request) {
	p, ok := authz.Require(w, r, authz.RoleSecurity)
	if !ok {
		return
	}
	key := r.PathValue("key")
	system, err := ParseKey(key)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	tester, ok := h.testers.Tester(system)
	if !ok {
		httpx.WriteError(w, http.StatusNotImplemented, "no live connection test is available for "+system+" in this build")
		return
	}
	// The test and the recording of its result outlive a client that
	// disconnects: the outcome is always recorded.
	ctx := context.WithoutCancel(r.Context())
	row, err := h.store.GetIntegration(ctx, key)
	if err != nil {
		h.fail(w, "test integration", err)
		return
	}
	start := time.Now()
	var res TestResult
	resolved, err := h.store.Resolve(ctx, key)
	switch {
	case errors.Is(err, ErrNotConfigured):
		// e.g. a secret missing from the store: a failed test, not a 404.
		res = TestResult{Error: Sanitize(err.Error(), nil)}
	case err != nil:
		h.internal(w, "test integration", err)
		return
	default:
		row = resolved.Integration
		if terr := h.runTester(ctx, tester, resolved); terr != nil {
			res = TestResult{Error: Sanitize(terr.Error(), resolved.Secrets)}
		} else {
			res = TestResult{OK: true}
		}
	}
	res.Duration = time.Since(start)
	in, err := h.store.RecordTest(ctx, key, row.UpdatedAt, res, p.Actor())
	if errors.Is(err, ErrChanged) {
		httpx.WriteError(w, http.StatusConflict, ErrChanged.Error())
		return
	}
	if err != nil {
		h.fail(w, "record integration test", err)
		return
	}
	h.log.Info("integration tested", "key", key, "actor", p.Actor(), "ok", res.OK, "error", res.Error, "duration_ms", res.Duration.Milliseconds())
	httpx.WriteJSON(w, http.StatusOK, TestResponse{OK: res.OK, Error: res.Error, DurationMS: res.Duration.Milliseconds(), Integration: h.view(in)})
}

// runTester runs one test with the timeout. A tester that ignores its
// context is abandoned at the deadline (its goroutine finishes on its own);
// a panic is a failed test.
func (h *Handler) runTester(parent context.Context, t Tester, r Resolved) error {
	ctx, cancel := context.WithTimeout(parent, h.testTimeout)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				done <- errors.New("connection test crashed (internal error)")
			}
		}()
		done <- t.Test(ctx, copyResolved(r))
	}()
	select {
	case err := <-done:
		if err != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("connection test timed out after %s: %w", h.testTimeout, err)
		}
		return err
	case <-ctx.Done():
		return fmt.Errorf("connection test timed out after %s", h.testTimeout)
	}
}

// fail maps store errors to responses. Messages of ErrInvalid errors are
// written by this package and never contain secret values.
func (h *Handler) fail(w http.ResponseWriter, op string, err error) {
	switch {
	case errors.Is(err, ErrInvalid):
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, ErrNotConfigured):
		httpx.WriteError(w, http.StatusNotFound, "integration not configured")
	case errors.Is(err, secrets.ErrReadOnly):
		httpx.WriteError(w, http.StatusConflict, "the secret provider is read-only: set secrets.provider to encfile or vault to manage credentials from the console")
	default:
		h.internal(w, op, err)
	}
}

func (h *Handler) internal(w http.ResponseWriter, op string, err error) {
	// Store errors name secrets but never contain values.
	h.log.Error(op+" failed", "err", err)
	httpx.WriteError(w, http.StatusInternalServerError, op+" failed (see server log)")
}
