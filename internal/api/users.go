package api

import (
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/unveiledhistory49/gatekeeper/internal/auth"
	"github.com/unveiledhistory49/gatekeeper/internal/store"
)

func (d Deps) sessionTTL() time.Duration {
	if d.Cfg.SessionHours <= 0 {
		return 12 * time.Hour
	}
	return time.Duration(d.Cfg.SessionHours) * time.Hour
}

func (d Deps) handleLogin(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var body struct {
		OrgID    string `json:"org_id"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decodeBody(raw, &body); err != nil {
		errJSON(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.OrgID == "" || body.Email == "" || body.Password == "" {
		errJSON(w, http.StatusBadRequest, "org_id, email and password are required")
		return
	}
	u, err := d.Store.GetUserByEmail(r.Context(), body.OrgID, body.Email)
	if err != nil {
		errJSON(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if u.Status != "active" || !auth.CheckPassword(u.PasswordHash, body.Password) {
		errJSON(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	token, th := auth.NewSessionToken()
	exp := time.Now().Add(d.sessionTTL()).Unix()
	now := time.Now().Unix()
	if err := d.Store.CreateSession(r.Context(), store.Session{
		ID: newID(), OrgID: u.OrgID, UserID: u.ID,
		TokenHash: th, CreatedAt: now, ExpiresAt: exp,
	}); err != nil {
		errJSON(w, http.StatusInternalServerError, "cannot create session")
		return
	}
	_, _ = d.Store.AppendAudit(r.Context(), u.OrgID, u.ID, "users.login", u.ID, "", now)
	http.SetCookie(w, &http.Cookie{
		Name: "gk_session", Value: token, Path: "/", HttpOnly: true,
		Secure:  r.TLS != nil,
		Expires: time.Unix(exp, 0), MaxAge: int(d.sessionTTL().Seconds()), SameSite: http.SameSiteLaxMode,
	})
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "expires_at": exp})
}

func (d Deps) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("gk_session"); err == nil && c.Value != "" {
		if se, err := d.Store.GetSessionByHash(r.Context(), auth.HashSessionToken(c.Value)); err == nil {
			_ = d.Store.DeleteSession(r.Context(), se.ID)
		}
	}
	http.SetCookie(w, &http.Cookie{Name: "gk_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: r.TLS != nil})
	d.audit(r.Context(), "users.logout", "", "")
	w.WriteHeader(http.StatusNoContent)
}

func (d Deps) handleMe(w http.ResponseWriter, r *http.Request) {
	id, ok := auth.IdentityFrom(r.Context())
	if !ok {
		errJSON(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if id.Kind == "api_key" || id.UserID == "" {
		// Service keys authenticate org identity but satisfy no RBAC
		// permission (see ADR-0002). Report none here so callers are not
		// misled by Require() later returning 403.
		writeJSON(w, http.StatusOK, map[string]any{
			"org_id": id.OrgID, "user_id": "", "kind": "api_key",
			"user": nil, "permissions": []string{},
			"note": "service keys do not satisfy RBAC; use a user session",
		})
		return
	}
	u, err := d.Store.GetUser(r.Context(), id.OrgID, id.UserID)
	if err != nil {
		errJSON(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	perms, _ := d.Store.UserPermissions(r.Context(), id.UserID)
	roles, _ := d.Store.UserRoles(r.Context(), id.UserID)
	writeJSON(w, http.StatusOK, map[string]any{
		"org_id": id.OrgID, "user_id": id.UserID, "kind": id.Kind,
		"user": publicUser(u), "permissions": perms, "roles": roles,
	})
}

func publicUser(u store.User) map[string]any {
	return map[string]any{
		"id": u.ID, "org_id": u.OrgID, "email": u.Email,
		"name": u.Name, "status": u.Status, "created_at": u.CreatedAt,
	}
}

func (d Deps) handleCreateUser(w http.ResponseWriter, r *http.Request) {
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
		Email    string   `json:"email"`
		Name     string   `json:"name"`
		Password string   `json:"password"`
		RoleIDs  []string `json:"role_ids"`
	}
	if err := decodeBody(raw, &body); err != nil {
		errJSON(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.Email == "" || body.Name == "" || body.Password == "" {
		errJSON(w, http.StatusBadRequest, "email, name and password are required")
		return
	}
	ph, err := auth.HashPassword(body.Password)
	if err != nil {
		errJSON(w, http.StatusBadRequest, "invalid password: "+err.Error())
		return
	}
	u := store.User{
		ID: newID(), OrgID: orgID, Email: body.Email, Name: body.Name,
		PasswordHash: ph, Status: "active", CreatedAt: time.Now().Unix(),
	}
	if err := d.Store.CreateUser(r.Context(), u); err != nil {
		if errors.Is(err, store.ErrConflict) {
			errJSON(w, http.StatusConflict, "user already exists")
			return
		}
		errJSON(w, http.StatusInternalServerError, "cannot create user")
		return
	}
	if len(body.RoleIDs) > 0 {
		if err := d.Store.SetUserRoles(r.Context(), orgID, u.ID, body.RoleIDs); err != nil {
			errJSON(w, http.StatusBadRequest, "invalid role_ids")
			return
		}
	}
	d.audit(r.Context(), "users.create", u.ID, body.Email)
	resp := publicUser(u)
	if len(body.RoleIDs) > 0 {
		resp["role_ids"] = body.RoleIDs
	}
	b := marshal(resp)
	d.storeReplay(r.Context(), orgID, key, r.Method, r.URL.Path, raw, http.StatusCreated, b)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write(b)
}

func (d Deps) handleListUsers(w http.ResponseWriter, r *http.Request) {
	orgID, ok := orgOf(r.Context())
	if !ok {
		errJSON(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	limit, offset := paginate(r)
	users, err := d.Store.ListUsers(r.Context(), orgID, limit, offset)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "cannot list users")
		return
	}
	out := make([]map[string]any, 0, len(users))
	for _, u := range users {
		out = append(out, publicUser(u))
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out, "limit": limit, "offset": offset})
}

func roleIDsOf(roles []store.Role) []string {
	ids := make([]string, 0, len(roles))
	for _, r := range roles {
		ids = append(ids, r.ID)
	}
	return ids
}

func (d Deps) handleGetUser(w http.ResponseWriter, r *http.Request) {
	orgID, ok := orgOf(r.Context())
	if !ok {
		errJSON(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	u, err := d.Store.GetUser(r.Context(), orgID, chi.URLParam(r, "id"))
	if err != nil {
		errJSON(w, http.StatusNotFound, "user not found")
		return
	}
	roles, _ := d.Store.UserRoles(r.Context(), u.ID)
	resp := publicUser(u)
	resp["role_ids"] = roleIDsOf(roles)
	writeJSON(w, http.StatusOK, resp)
}

func (d Deps) handlePatchUser(w http.ResponseWriter, r *http.Request) {
	orgID, ok := orgOf(r.Context())
	if !ok {
		errJSON(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := chi.URLParam(r, "id")
	var body struct {
		Status *string `json:"status"`
		Name   *string `json:"name"`
	}
	if err := decodeJSON(r, &body); err != nil {
		errJSON(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.Status != nil {
		if *body.Status != "active" && *body.Status != "suspended" {
			errJSON(w, http.StatusBadRequest, "status must be active or suspended")
			return
		}
		if err := d.Store.SetUserStatus(r.Context(), orgID, id, *body.Status); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				errJSON(w, http.StatusNotFound, "user not found")
				return
			}
			errJSON(w, http.StatusBadRequest, err.Error())
			return
		}
		d.audit(r.Context(), "users.set_status", id, *body.Status)
	}
	if body.Name != nil {
		if *body.Name == "" {
			errJSON(w, http.StatusBadRequest, "name must not be empty")
			return
		}
		if err := d.Store.RenameUser(r.Context(), orgID, id, *body.Name); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				errJSON(w, http.StatusNotFound, "user not found")
				return
			}
			errJSON(w, http.StatusBadRequest, err.Error())
			return
		}
		d.audit(r.Context(), "users.update", id, *body.Name)
	}
	u, err := d.Store.GetUser(r.Context(), orgID, id)
	if err != nil {
		errJSON(w, http.StatusNotFound, "user not found")
		return
	}
	writeJSON(w, http.StatusOK, publicUser(u))
}

func (d Deps) handleSetUserRoles(w http.ResponseWriter, r *http.Request) {
	orgID, ok := orgOf(r.Context())
	if !ok {
		errJSON(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := chi.URLParam(r, "id")
	var body struct {
		RoleIDs []string `json:"role_ids"`
	}
	if err := decodeJSON(r, &body); err != nil {
		errJSON(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.RoleIDs == nil {
		body.RoleIDs = []string{}
	}
	if err := d.Store.SetUserRoles(r.Context(), orgID, id, body.RoleIDs); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			errJSON(w, http.StatusNotFound, "user or role not found")
			return
		}
		errJSON(w, http.StatusBadRequest, "invalid role_ids")
		return
	}
	d.audit(r.Context(), "users.set_roles", id, "")
	writeJSON(w, http.StatusOK, map[string]any{"user_id": id, "role_ids": body.RoleIDs})
}
