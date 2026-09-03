package api

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/unveiledhistory49/gatekeeper/internal/auth"
	"github.com/unveiledhistory49/gatekeeper/internal/store"
)

func randState() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func (d Deps) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	if !d.Cfg.OIDCEnabled() {
		errJSON(w, http.StatusNotImplemented, "oidc not configured")
		return
	}
	if d.OAuth == nil {
		errJSON(w, http.StatusNotImplemented, "oidc not configured")
		return
	}
	http.Redirect(w, r, d.OAuth.AuthCodeURL(randState()), http.StatusFound)
}

func (d Deps) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if !d.Cfg.OIDCEnabled() {
		errJSON(w, http.StatusNotImplemented, "oidc not configured")
		return
	}
	if d.OAuth == nil || d.OIDC == nil {
		errJSON(w, http.StatusNotImplemented, "oidc not configured")
		return
	}
	code := r.URL.Query().Get("code")
	orgID := r.URL.Query().Get("org_id")
	if code == "" || orgID == "" {
		errJSON(w, http.StatusBadRequest, "code and org_id are required")
		return
	}
	rawToken, err := d.OAuth.Exchange(r.Context(), code)
	if err != nil {
		errJSON(w, http.StatusBadGateway, "oidc exchange failed")
		return
	}
	claims, err := d.OIDC.Verify(r.Context(), rawToken)
	if err != nil || claims.Email == "" || claims.Subject == "" {
		errJSON(w, http.StatusBadGateway, "oidc verification failed")
		return
	}
	ctx := r.Context()
	now := time.Now().Unix()
	name := claims.Name
	if name == "" {
		name = claims.Email
	}
	// Find-or-create by OIDC link, else by email, else create.
	u, err := d.Store.GetOIDCUser(ctx, orgID, "oidc", claims.Subject)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			errJSON(w, http.StatusInternalServerError, "oidc login failed")
			return
		}
		u, err = d.Store.GetUserByEmail(ctx, orgID, claims.Email)
		if err != nil {
			if !errors.Is(err, store.ErrNotFound) {
				errJSON(w, http.StatusInternalServerError, "oidc login failed")
				return
			}
			// Users need a non-empty password_hash; store an unusable
			// argon2id hash over a random marker (prefix keeps it ≥12 chars).
			ph, herr := auth.HashPassword("oidc-placeholder-" + claims.Subject)
			if herr != nil {
				errJSON(w, http.StatusInternalServerError, "oidc login failed")
				return
			}
			u = store.User{
				ID: newID(), OrgID: orgID, Email: claims.Email, Name: name,
				PasswordHash: ph, Status: "active", CreatedAt: now,
			}
			if err := d.Store.CreateUser(ctx, u); err != nil {
				errJSON(w, http.StatusInternalServerError, "oidc login failed")
				return
			}
		}
		if lerr := d.Store.LinkOIDC(ctx, orgID, "oidc", claims.Subject, u.ID, now); lerr != nil && !errors.Is(lerr, store.ErrConflict) {
			errJSON(w, http.StatusInternalServerError, "oidc login failed")
			return
		}
	}
	if u.Status != "active" {
		errJSON(w, http.StatusForbidden, "account suspended")
		return
	}
	token, th := auth.NewSessionToken()
	exp := time.Now().Add(d.sessionTTL()).Unix()
	if err := d.Store.CreateSession(ctx, store.Session{
		ID: newID(), OrgID: orgID, UserID: u.ID,
		TokenHash: th, CreatedAt: now, ExpiresAt: exp,
	}); err != nil {
		errJSON(w, http.StatusInternalServerError, "cannot create session")
		return
	}
	_, _ = d.Store.AppendAudit(ctx, orgID, u.ID, "users.oidc_login", u.ID, "", now)
	http.SetCookie(w, &http.Cookie{
		Name: "gk_session", Value: token, Path: "/", HttpOnly: true,
		Expires: time.Unix(exp, 0), MaxAge: int(d.sessionTTL().Seconds()), SameSite: http.SameSiteLaxMode,
	})
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "expires_at": exp})
}
