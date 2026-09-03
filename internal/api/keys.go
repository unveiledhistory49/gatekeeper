package api

import (
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/unveiledhistory49/gatekeeper/internal/auth"
	"github.com/unveiledhistory49/gatekeeper/internal/store"
)

func (d Deps) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	orgID, ok := orgOf(r.Context())
	if !ok {
		errJSON(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	key := idemKey(r)
	if d.tryReplay(w, r, orgID, key, raw) {
		return
	}
	var body struct {
		Name           string `json:"name"`
		ExpiresInHours *int   `json:"expires_in_hours"`
	}
	if err := decodeBody(raw, &body); err != nil {
		errJSON(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.Name == "" {
		errJSON(w, http.StatusBadRequest, "name is required")
		return
	}
	rawKey, hash, prefix := auth.NewAPIKey(d.Cfg.Pepper)
	now := time.Now().Unix()
	var exp int64
	if body.ExpiresInHours != nil && *body.ExpiresInHours > 0 {
		exp = now + int64(*body.ExpiresInHours)*3600
	}
	k := store.APIKey{
		ID: newID(), OrgID: orgID, Name: body.Name, KeyHash: hash,
		Prefix: prefix, ExpiresAt: exp, Revoked: false, CreatedAt: now,
	}
	if err := d.Store.CreateAPIKey(r.Context(), k); err != nil {
		errJSON(w, http.StatusInternalServerError, "cannot create api key")
		return
	}
	d.audit(r.Context(), "keys.create", k.ID, body.Name)
	resp := map[string]any{
		"id": k.ID, "name": k.Name, "prefix": k.Prefix,
		"api_key": rawKey, "expires_at": k.ExpiresAt, "created_at": k.CreatedAt,
	}
	b := marshal(resp)
	d.storeReplay(r.Context(), orgID, key, r.Method, r.URL.Path, raw, http.StatusCreated, b)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write(b)
}

func (d Deps) handleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	orgID, ok := orgOf(r.Context())
	if !ok {
		errJSON(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	keys, err := d.Store.ListAPIKeys(r.Context(), orgID)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "cannot list api keys")
		return
	}
	out := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		out = append(out, map[string]any{
			"id": k.ID, "name": k.Name, "prefix": k.Prefix,
			"revoked": k.Revoked, "expires_at": k.ExpiresAt, "created_at": k.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"api_keys": out})
}

func (d Deps) handleRevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	orgID, ok := orgOf(r.Context())
	if !ok {
		errJSON(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := chi.URLParam(r, "id")
	if err := d.Store.RevokeAPIKey(r.Context(), orgID, id); err != nil {
		errJSON(w, http.StatusNotFound, "api key not found")
		return
	}
	d.audit(r.Context(), "keys.revoke", id, "")
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "revoked": true})
}
