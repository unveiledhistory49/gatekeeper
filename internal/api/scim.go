package api

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/unveiledhistory49/gatekeeper/internal/auth"
	"github.com/unveiledhistory49/gatekeeper/internal/store"
)

const scimSchemaUser = "urn:ietf:params:scim:schemas:core:2.0:User"
const scimSchemaList = "urn:ietf:params:scim:api:messages:2.0:ListResponse"

func scimUser(u store.User) map[string]any {
	return map[string]any{
		"schemas":     []string{scimSchemaUser},
		"id":          u.ID,
		"userName":    u.Email,
		"displayName": u.Name,
		"active":      u.Status == "active",
		"meta": map[string]any{
			"resourceType": "User",
			"created":      time.Unix(u.CreatedAt, 0).UTC().Format(time.RFC3339),
		},
	}
}

func (d Deps) handleSCIMList(w http.ResponseWriter, r *http.Request) {
	orgID, ok := orgOf(r.Context())
	if !ok {
		errJSON(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	startIndex := 1
	count := 100
	if v := r.URL.Query().Get("startIndex"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 {
			startIndex = n
		}
	}
	if v := r.URL.Query().Get("count"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			count = n
		}
	}
	if count > 200 {
		count = 200
	}
	users, err := d.Store.ListUsers(r.Context(), orgID, count, startIndex-1)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "cannot list users")
		return
	}
	res := make([]map[string]any, 0, len(users))
	for _, u := range users {
		res = append(res, scimUser(u))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"schemas":      []string{scimSchemaList},
		"totalResults": len(res),
		"startIndex":   startIndex,
		"itemsPerPage": count,
		"Resources":    res,
	})
}

func (d Deps) handleSCIMCreate(w http.ResponseWriter, r *http.Request) {
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
		UserName    string `json:"userName"`
		DisplayName string `json:"displayName"`
		Password    string `json:"password"`
		Active      *bool  `json:"active"`
	}
	if err := decodeBody(raw, &body); err != nil {
		errJSON(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.UserName == "" || body.Password == "" {
		errJSON(w, http.StatusBadRequest, "userName and password are required")
		return
	}
	name := body.DisplayName
	if name == "" {
		name = body.UserName
	}
	ph, err := auth.HashPassword(body.Password)
	if err != nil {
		errJSON(w, http.StatusBadRequest, "invalid password: "+err.Error())
		return
	}
	now := time.Now().Unix()
	u := store.User{
		ID: newID(), OrgID: orgID, Email: body.UserName, Name: name,
		PasswordHash: ph, Status: "active", CreatedAt: now,
	}
	if err := d.Store.CreateUser(r.Context(), u); err != nil {
		if errors.Is(err, store.ErrConflict) {
			errJSON(w, http.StatusConflict, "user already exists")
			return
		}
		errJSON(w, http.StatusInternalServerError, "cannot create user")
		return
	}
	if body.Active != nil && !*body.Active {
		_ = d.Store.SetUserStatus(r.Context(), orgID, u.ID, "suspended")
		u.Status = "suspended"
	}
	d.audit(r.Context(), "users.create", u.ID, body.UserName)
	b := marshal(scimUser(u))
	d.storeReplay(r.Context(), orgID, key, r.Method, r.URL.Path, raw, http.StatusCreated, b)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write(b)
}

func (d Deps) handleSCIMGet(w http.ResponseWriter, r *http.Request) {
	orgID, ok := orgOf(r.Context())
	if !ok {
		errJSON(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	u, err := d.Store.GetUser(r.Context(), orgID, chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
			"detail":  "user not found", "status": "404",
		})
		return
	}
	writeJSON(w, http.StatusOK, scimUser(u))
}
