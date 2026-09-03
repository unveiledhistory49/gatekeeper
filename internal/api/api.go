package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/unveiledhistory49/gatekeeper/internal/auth"
	"github.com/unveiledhistory49/gatekeeper/internal/config"
	"github.com/unveiledhistory49/gatekeeper/internal/rbac"
	"github.com/unveiledhistory49/gatekeeper/internal/store"
)

type Deps struct {
	Store *store.Store
	Auth  *auth.Authenticator
	Cfg   config.Config
	OIDC  auth.Verifier
	OAuth *auth.OAuthClient
}

func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// guard wraps h with an RBAC permission check, returning an http.HandlerFunc
// for chi registration.
func (d Deps) guard(need string, h func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return rbac.Require(d.Store, need, http.HandlerFunc(h)).ServeHTTP
}

func NewRouter(d Deps) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID, middleware.Recoverer)
	r.NotFound(func(w http.ResponseWriter, req *http.Request) { errJSON(w, http.StatusNotFound, "not found") })
	r.MethodNotAllowed(func(w http.ResponseWriter, req *http.Request) {
		errJSON(w, http.StatusMethodNotAllowed, "method not allowed")
	})

	r.Get("/healthz", d.handleHealthz)

	// Public: login + OIDC handshake must work without credentials, so they
	// sit outside the Auth.Middleware group even though they live under /v1.
	r.Post("/v1/login", d.handleLogin)
	r.Get("/v1/oidc/login", d.handleOIDCLogin)
	r.Get("/v1/oidc/callback", d.handleOIDCCallback)

	r.Group(func(r chi.Router) {
		r.Use(d.Auth.Middleware)
		r.Post("/v1/logout", d.handleLogout)
		r.Get("/v1/me", d.handleMe)

		r.Post("/v1/users", d.guard("users:write", d.handleCreateUser))
		r.Get("/v1/users", d.guard("users:read", d.handleListUsers))
		r.Get("/v1/users/{id}", d.guard("users:read", d.handleGetUser))
		r.Patch("/v1/users/{id}", d.guard("users:write", d.handlePatchUser))
		r.Post("/v1/users/{id}/roles", d.guard("users:write", d.handleSetUserRoles))

		r.Post("/v1/roles", d.guard("roles:write", d.handleCreateRole))
		r.Get("/v1/roles", d.guard("roles:read", d.handleListRoles))
		r.Post("/v1/roles/{id}/permissions", d.guard("roles:write", d.handleSetRolePermissions))

		r.Post("/v1/api-keys", d.guard("keys:write", d.handleCreateAPIKey))
		r.Get("/v1/api-keys", d.guard("keys:read", d.handleListAPIKeys))
		r.Post("/v1/api-keys/{id}/revoke", d.guard("keys:write", d.handleRevokeAPIKey))

		r.Post("/v1/reviews/campaigns", d.guard("reviews:write", d.handleCreateCampaign))
		r.Get("/v1/reviews/campaigns", d.guard("reviews:read", d.handleListCampaigns))
		r.Get("/v1/reviews/campaigns/{id}/items", d.guard("reviews:read", d.handleListItems))
		r.Post("/v1/reviews/items/{itemID}/decide", d.guard("reviews:write", d.handleDecideItem))
		r.Post("/v1/reviews/campaigns/{id}/close", d.guard("reviews:write", d.handleCloseCampaign))

		r.Get("/v1/audit", d.guard("audit:read", d.handleListAudit))
		r.Get("/v1/audit/verify", d.guard("audit:read", d.handleVerifyAudit))
	})

	r.Route("/scim/v2", func(r chi.Router) {
		r.Use(d.Auth.Middleware)
		r.Get("/Users", d.guard("users:read", d.handleSCIMList))
		r.Post("/Users", d.guard("users:write", d.handleSCIMCreate))
		r.Get("/Users/{id}", d.guard("users:read", d.handleSCIMGet))
	})

	return r
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func errJSON(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func decodeJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func actorOf(ctx context.Context) string {
	if id, ok := auth.IdentityFrom(ctx); ok {
		if id.UserID != "" {
			return id.UserID
		}
		return "api_key"
	}
	return "anonymous"
}

func orgOf(ctx context.Context) (string, bool) {
	id, ok := auth.IdentityFrom(ctx)
	if !ok || id.OrgID == "" {
		return "", false
	}
	return id.OrgID, true
}

func (d Deps) audit(ctx context.Context, action, target, detail string) {
	orgID, ok := orgOf(ctx)
	if !ok {
		return
	}
	// Audit writes must never fail silently: a mutation without its audit row
	// is an integrity gap. The mutation already committed, so we cannot roll
	// back — log loudly for operators instead (alert on "AUDIT_GAP").
	if _, err := d.Store.AppendAudit(ctx, orgID, actorOf(ctx), action, target, detail, time.Now().Unix()); err != nil {
		log.Printf("AUDIT_GAP org=%s action=%s target=%s err=%v", orgID, action, target, err)
	}
}

func paginate(r *http.Request) (limit, offset int) {
	limit, offset = 50, 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	if limit > 200 {
		limit = 200
	}
	return limit, offset
}

func reqHash(raw []byte) string {
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

func idemKey(r *http.Request) string {
	if k := r.Header.Get("Idempotency-Key"); k != "" {
		return k
	}
	return r.URL.Query().Get("idempotency_key")
}

// tryReplay implements the idemReplay pattern. It returns true when it has
// already written the response (replay, or 422/409 for a bad key).
func (d Deps) tryReplay(w http.ResponseWriter, r *http.Request, orgID, key string, raw []byte) bool {
	if key == "" {
		return false
	}
	if len(key) < 8 || len(key) > 64 {
		errJSON(w, 422, "invalid idempotency key")
		return true
	}
	_, _, storedHash, status, body, err := d.Store.IdemGet(r.Context(), orgID, key)
	if err != nil {
		return false // ErrNotFound → proceed
	}
	if storedHash != reqHash(raw) {
		errJSON(w, http.StatusConflict, "idempotency key already used with different request")
		return true
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
	return true
}

func (d Deps) storeReplay(ctx context.Context, orgID, key, method, path string, raw []byte, status int, respBody []byte) {
	if key == "" {
		return
	}
	_ = d.Store.IdemPut(ctx, orgID, key, method, path, reqHash(raw), status, string(respBody), time.Now().Unix())
}

func marshal(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func (d Deps) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "version": "1.0.0", "time": time.Now().UTC().Format(time.RFC3339)})
}
