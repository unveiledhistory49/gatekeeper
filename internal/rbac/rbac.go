// Package rbac enforces permission checks on already-authenticated requests.
//
// Posture (documented decision): API keys are accepted at the identity layer
// (see internal/auth) as org-scoped service identities with no UserID and no
// roles. Require denies such identities with 403: service automation that
// needs RBAC-protected endpoints must use a user session token. The schema is
// frozen (api_keys gains no user column), so there is no safe way to attach
// least-privilege role grants to a key; failing closed beats inventing
// ambient authority.
package rbac

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/unveiledhistory49/gatekeeper/internal/auth"
	"github.com/unveiledhistory49/gatekeeper/internal/store"
)

// Granted reports whether the permission set perms grants need. A grant
// matches when it equals need exactly, when it is the wildcard "*", or when
// it is a namespace wildcard "ns:*" and need has the form "ns:anything"
// (need is split on its first colon). A single-segment need (no colon)
// matches only an exact entry or "*".
func Granted(perms []string, need string) bool {
	for _, p := range perms {
		if p == need || p == "*" {
			return true
		}
		if strings.HasSuffix(p, ":*") {
			if i := strings.IndexByte(need, ':'); i >= 0 {
				if p == need[:i]+":*" {
					return true
				}
			}
		}
	}
	return false
}

// writeJSON renders a JSON error body with the given status code.
func writeJSON(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// Require returns middleware that enforces the need permission for the
// request's auth.Identity. Missing identity yields 401; api_key identities
// (empty UserID) yield 403 since service keys carry no roles — see the
// package comment. Otherwise the user's permissions are loaded via
// Store.UserPermissions and the request proceeds only on Granted.
func Require(st *store.Store, need string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := auth.IdentityFrom(r.Context())
		if !ok {
			writeJSON(w, http.StatusUnauthorized, "unauthenticated")
			return
		}
		if id.UserID == "" {
			writeJSON(w, http.StatusForbidden, "service keys cannot satisfy RBAC; use a user session")
			return
		}
		perms, err := st.UserPermissions(r.Context(), id.UserID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, "cannot load permissions")
			return
		}
		if !Granted(perms, need) {
			writeJSON(w, http.StatusForbidden, "forbidden")
			return
		}
		next.ServeHTTP(w, r)
	})
}
