package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/unveiledhistory49/gatekeeper/internal/store"
)

func decodeBody(raw []byte, v any) error {
	return json.Unmarshal(raw, v)
}

func (d Deps) handleCreateRole(w http.ResponseWriter, r *http.Request) {
	orgID, ok := orgOf(r.Context())
	if !ok {
		errJSON(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var body struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Permissions []string `json:"permissions"`
	}
	if err := decodeJSON(r, &body); err != nil {
		errJSON(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.Name == "" {
		errJSON(w, http.StatusBadRequest, "name is required")
		return
	}
	if body.Permissions == nil {
		body.Permissions = []string{}
	}
	role := store.Role{
		ID: newID(), OrgID: orgID, Name: body.Name,
		Description: body.Description, CreatedAt: time.Now().Unix(),
	}
	if err := d.Store.CreateRole(r.Context(), role); err != nil {
		if errors.Is(err, store.ErrConflict) {
			errJSON(w, http.StatusConflict, "role already exists")
			return
		}
		errJSON(w, http.StatusInternalServerError, "cannot create role")
		return
	}
	if err := d.Store.SetRolePermissions(r.Context(), role.ID, body.Permissions); err != nil {
		errJSON(w, http.StatusBadRequest, "invalid permissions")
		return
	}
	d.audit(r.Context(), "roles.create", role.ID, body.Name)
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": role.ID, "org_id": role.OrgID, "name": role.Name,
		"description": role.Description, "created_at": role.CreatedAt,
		"permissions": body.Permissions,
	})
}

func (d Deps) handleListRoles(w http.ResponseWriter, r *http.Request) {
	orgID, ok := orgOf(r.Context())
	if !ok {
		errJSON(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	roles, err := d.Store.ListRoles(r.Context(), orgID)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "cannot list roles")
		return
	}
	out := make([]map[string]any, 0, len(roles))
	for _, role := range roles {
		perms, _ := d.Store.RolePermissions(r.Context(), role.ID)
		out = append(out, map[string]any{
			"id": role.ID, "org_id": role.OrgID, "name": role.Name,
			"description": role.Description, "created_at": role.CreatedAt,
			"permissions": perms,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"roles": out})
}

func (d Deps) handleSetRolePermissions(w http.ResponseWriter, r *http.Request) {
	orgID, ok := orgOf(r.Context())
	if !ok {
		errJSON(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := chi.URLParam(r, "id")
	if _, err := d.Store.GetRole(r.Context(), orgID, id); err != nil {
		errJSON(w, http.StatusNotFound, "role not found")
		return
	}
	var body struct {
		Set []string `json:"set"`
	}
	if err := decodeJSON(r, &body); err != nil {
		errJSON(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.Set == nil {
		body.Set = []string{}
	}
	if err := d.Store.SetRolePermissions(r.Context(), id, body.Set); err != nil {
		errJSON(w, http.StatusBadRequest, "invalid permissions")
		return
	}
	d.audit(r.Context(), "roles.set_permissions", id, "")
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "permissions": body.Set})
}
