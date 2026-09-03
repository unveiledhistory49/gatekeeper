package rbac_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/unveiledhistory49/gatekeeper/internal/auth"
	"github.com/unveiledhistory49/gatekeeper/internal/db"
	"github.com/unveiledhistory49/gatekeeper/internal/rbac"
	"github.com/unveiledhistory49/gatekeeper/internal/store"
)

func TestGranted(t *testing.T) {
	cases := []struct {
		name  string
		perms []string
		need  string
		want  bool
	}{
		{"exact match", []string{"users:read"}, "users:read", true},
		{"exact miss", []string{"users:read"}, "users:write", false},
		{"empty perms", nil, "users:read", false},
		{"empty need exact", []string{""}, "", true},
		{"global wildcard", []string{"*"}, "users:read", true},
		{"global wildcard single segment", []string{"*"}, "admin", true},
		{"global wildcard among others", []string{"users:read", "*"}, "anything:at:all", true},
		{"namespace wildcard", []string{"users:*"}, "users:read", true},
		{"namespace wildcard write", []string{"users:*"}, "users:write", true},
		{"namespace wildcard deep need", []string{"users:*"}, "users:read:extra", true},
		{"namespace wildcard other ns", []string{"users:*"}, "roles:read", false},
		{"namespace wildcard prefix only", []string{"users:*"}, "users", false},
		{"namespace wildcard empty suffix", []string{"users:*"}, "users:", true},
		{"single segment exact", []string{"admin"}, "admin", true},
		{"single segment miss", []string{"admin"}, "root", false},
		{"single segment vs wildcard ns", []string{"users:*"}, "admin", false},
		{"need without colon vs star-ns", []string{"*:*"}, "admin", false},
		{"star-ns pattern matches colon need", []string{"*:*"}, "*:read", true},
		{"unrelated wildcard", []string{"audit:*"}, "users:read", false},
		{"multiple perms hit", []string{"roles:read", "users:write"}, "users:write", true},
		{"multiple perms miss", []string{"roles:read", "users:write"}, "users:delete", false},
		{"case sensitive", []string{"Users:read"}, "users:read", false},
		{"wildcard not suffix", []string{"*:read"}, "*:read", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := rbac.Granted(tc.perms, tc.need); got != tc.want {
				t.Errorf("Granted(%q, %q) = %v, want %v", tc.perms, tc.need, got, tc.want)
			}
		})
	}
}

// newTestStore opens a migrated in-memory SQLite store for tests.
func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	pool, driver, err := db.Open("sqlite://:memory:")
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if err := db.Migrate(pool); err != nil {
		t.Fatalf("db.Migrate: %v", err)
	}
	t.Cleanup(func() { _ = pool.Close() })
	return store.New(pool, driver)
}

func execSQL(t *testing.T, s *store.Store, query string, args ...any) {
	t.Helper()
	if _, err := s.DB.Exec(query, args...); err != nil {
		t.Fatalf("exec %q: %v", query, err)
	}
}

// seedUserWithPerms creates org/user/role wiring granting perms to userID.
func seedUserWithPerms(t *testing.T, s *store.Store, orgID, userID string, perms []string) {
	t.Helper()
	now := time.Now().Unix()
	execSQL(t, s, `INSERT INTO orgs(id, name, created_at) VALUES (?, ?, ?)`, orgID, "org-"+orgID, now)
	execSQL(t, s, `INSERT INTO users(id, org_id, email, name, password_hash, status, created_at) VALUES (?, ?, ?, ?, ?, 'active', ?)`,
		userID, orgID, userID+"@example.com", "User "+userID, "", now)
	roleID := "r-" + userID
	execSQL(t, s, `INSERT INTO roles(id, org_id, name, description, created_at) VALUES (?, ?, ?, '', ?)`, roleID, orgID, "role-"+userID, now)
	execSQL(t, s, `INSERT INTO user_roles(user_id, role_id) VALUES (?, ?)`, userID, roleID)
	for _, p := range perms {
		execSQL(t, s, `INSERT INTO role_permissions(role_id, permission) VALUES (?, ?)`, roleID, p)
	}
}

func withIdentity(r *http.Request, id auth.Identity) *http.Request {
	return r.WithContext(auth.ContextWithIdentity(r.Context(), id))
}

func TestRequire(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("allows granted permission", func(t *testing.T) {
		s := newTestStore(t)
		seedUserWithPerms(t, s, "o1", "u1", []string{"users:read"})
		req := withIdentity(httptest.NewRequest(http.MethodGet, "/", nil),
			auth.Identity{OrgID: "o1", UserID: "u1", Kind: "session"})
		rec := httptest.NewRecorder()
		rbac.Require(s, "users:read", next).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("code = %d, want 200 (body %q)", rec.Code, rec.Body.String())
		}
	})

	t.Run("allows via namespace wildcard", func(t *testing.T) {
		s := newTestStore(t)
		seedUserWithPerms(t, s, "o1", "u1", []string{"users:*"})
		req := withIdentity(httptest.NewRequest(http.MethodGet, "/", nil),
			auth.Identity{OrgID: "o1", UserID: "u1", Kind: "session"})
		rec := httptest.NewRecorder()
		rbac.Require(s, "users:delete", next).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("code = %d, want 200", rec.Code)
		}
	})

	t.Run("denies missing permission with 403", func(t *testing.T) {
		s := newTestStore(t)
		seedUserWithPerms(t, s, "o1", "u1", []string{"users:read"})
		req := withIdentity(httptest.NewRequest(http.MethodGet, "/", nil),
			auth.Identity{OrgID: "o1", UserID: "u1", Kind: "session"})
		rec := httptest.NewRecorder()
		rbac.Require(s, "users:write", next).ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("code = %d, want 403", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), `"error"`) {
			t.Fatalf("body = %q, want JSON error", rec.Body.String())
		}
	})

	t.Run("denies user with no roles with 403", func(t *testing.T) {
		s := newTestStore(t)
		seedUserWithPerms(t, s, "o1", "u1", nil)
		req := withIdentity(httptest.NewRequest(http.MethodGet, "/", nil),
			auth.Identity{OrgID: "o1", UserID: "u1", Kind: "session"})
		rec := httptest.NewRecorder()
		rbac.Require(s, "users:read", next).ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("code = %d, want 403", rec.Code)
		}
	})

	t.Run("denies api_key identity with 403", func(t *testing.T) {
		s := newTestStore(t)
		seedUserWithPerms(t, s, "o1", "u1", []string{"*"})
		req := withIdentity(httptest.NewRequest(http.MethodGet, "/", nil),
			auth.Identity{OrgID: "o1", UserID: "", Kind: "api_key"})
		rec := httptest.NewRecorder()
		rbac.Require(s, "users:read", next).ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("code = %d, want 403", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "service keys cannot satisfy RBAC") {
			t.Fatalf("body = %q, want service-key posture message", rec.Body.String())
		}
	})

	t.Run("no identity yields 401", func(t *testing.T) {
		s := newTestStore(t)
		seedUserWithPerms(t, s, "o1", "u1", []string{"*"})
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		rbac.Require(s, "users:read", next).ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("code = %d, want 401", rec.Code)
		}
	})

	t.Run("end to end via middleware chain", func(t *testing.T) {
		s := newTestStore(t)
		seedUserWithPerms(t, s, "o1", "u1", []string{"users:read"})
		a := &auth.Authenticator{Store: s, Pepper: "p"}
		raw, h := auth.NewSessionToken()
		execSQL(t, s, `INSERT INTO sessions(id, org_id, user_id, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
			"s1", "o1", "u1", h, time.Now().Unix(), time.Now().Add(time.Hour).Unix())
		chain := a.Middleware(rbac.Require(s, "users:read", next))

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: "gk_session", Value: raw})
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("allowed chain code = %d, want 200", rec.Code)
		}

		rec2 := httptest.NewRecorder()
		rbac.Require(s, "users:write", next).ServeHTTP(rec2,
			withIdentity(httptest.NewRequest(http.MethodGet, "/", nil),
				auth.Identity{OrgID: "o1", UserID: "u1", Kind: "session"}))
		if rec2.Code != http.StatusForbidden {
			t.Fatalf("denied chain code = %d, want 403", rec2.Code)
		}
	})
}
