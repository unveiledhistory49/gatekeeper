package auth_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/unveiledhistory49/gatekeeper/internal/auth"
	"github.com/unveiledhistory49/gatekeeper/internal/db"
	"github.com/unveiledhistory49/gatekeeper/internal/store"
)

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

func seedOrgUser(t *testing.T, s *store.Store, orgID, userID, status string) {
	t.Helper()
	now := time.Now().Unix()
	// OR IGNORE: several users may share one org within a single test store.
	execSQL(t, s, `INSERT OR IGNORE INTO orgs(id, name, created_at) VALUES (?, ?, ?)`, orgID, "org-"+orgID, now)
	execSQL(t, s, `INSERT INTO users(id, org_id, email, name, password_hash, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		userID, orgID, userID+"@example.com", "User "+userID, "", status, now)
}

func seedSession(t *testing.T, s *store.Store, id, orgID, userID, tokenHash string, expiresAt int64) {
	t.Helper()
	now := time.Now().Unix()
	execSQL(t, s, `INSERT INTO sessions(id, org_id, user_id, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
		id, orgID, userID, tokenHash, now, expiresAt)
}

func seedAPIKey(t *testing.T, s *store.Store, id, orgID, keyHash, prefix string, expiresAt, revoked int64) {
	t.Helper()
	execSQL(t, s, `INSERT INTO api_keys(id, org_id, name, key_hash, prefix, expires_at, revoked, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		id, orgID, "key-"+id, keyHash, prefix, expiresAt, revoked, time.Now().Unix())
}

// okHandler asserts identity propagation when expect is non-nil, then 200s.
func okHandler(t *testing.T, expect *auth.Identity) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if expect != nil {
			got, ok := auth.IdentityFrom(r.Context())
			if !ok {
				t.Errorf("expected identity in context, got none")
			} else if got != *expect {
				t.Errorf("identity = %+v, want %+v", got, *expect)
			}
		}
		w.WriteHeader(http.StatusOK)
	})
}

func TestHashPassword(t *testing.T) {
	t.Run("roundtrip", func(t *testing.T) {
		for _, pw := range []string{"twelve-chars", "a much longer passphrase 123!", strings.Repeat("x", 64)} {
			enc, err := auth.HashPassword(pw)
			if err != nil {
				t.Fatalf("HashPassword(%q): %v", pw, err)
			}
			if !strings.HasPrefix(enc, "$argon2id$v=19$m=65536,t=3,p=4$") {
				t.Fatalf("encoded = %q, want $argon2id$v=19$m=65536,t=3,p=4$ prefix", enc)
			}
			segs := strings.Split(enc, "$")
			if len(segs) != 6 || strings.Contains(segs[4], "=") || strings.Contains(segs[5], "=") {
				t.Fatalf("encoded = %q, want unpadded base64 salt/hash", enc)
			}
			if !auth.CheckPassword(enc, pw) {
				t.Fatalf("CheckPassword roundtrip failed for %q", pw)
			}
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		enc, err := auth.HashPassword("correct-horse-123")
		if err != nil {
			t.Fatalf("HashPassword: %v", err)
		}
		for _, wrong := range []string{"correct-horse-124", "", "correct-horse-12", "correct-horse-1234"} {
			if auth.CheckPassword(enc, wrong) {
				t.Errorf("CheckPassword accepted wrong password %q", wrong)
			}
		}
	})

	t.Run("short password rejected", func(t *testing.T) {
		for _, pw := range []string{"", "x", "short-pw", "eleven-chr"} {
			if _, err := auth.HashPassword(pw); err == nil {
				t.Errorf("HashPassword(%q) = nil error, want rejection", pw)
			}
		}
	})

	t.Run("malformed hashes", func(t *testing.T) {
		good, err := auth.HashPassword("twelve-chars!!")
		if err != nil {
			t.Fatalf("HashPassword: %v", err)
		}
		parts := strings.Split(good, "$")
		tampered := "$" + strings.Join(parts[1:5], "$") + "$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		cases := map[string]string{
			"empty":          "",
			"junk":           "not-a-hash",
			"truncated":      "$argon2id$v=19$m=65536,t=3,p=4$onlysalt",
			"wrong scheme":   strings.Replace(good, "$argon2id$", "$bcrypt$", 1),
			"wrong version":  strings.Replace(good, "$v=19$", "$v=16$", 1),
			"bad params":     strings.Replace(good, "$m=65536,t=3,p=4$", "$m=oops$", 1),
			"zero params":    strings.Replace(good, "$m=65536,t=3,p=4$", "$m=0,t=0,p=0$", 1),
			"bad salt b64":   "$argon2id$v=19$m=65536,t=3,p=4$!!!$" + parts[5],
			"bad hash b64":   parts[0] + "$" + parts[1] + "$" + parts[2] + "$" + parts[3] + "$" + parts[4] + "$!!!",
			"tampered hash":  tampered,
			"padded b64":     good + "=",
			"missing prefix": strings.TrimPrefix(good, "$"),
		}
		for name, enc := range cases {
			if auth.CheckPassword(enc, "twelve-chars!!") {
				t.Errorf("CheckPassword(%s) = true, want false", name)
			}
		}
	})

	t.Run("salts differ", func(t *testing.T) {
		a, _ := auth.HashPassword("same-password!!")
		b, _ := auth.HashPassword("same-password!!")
		if a == b {
			t.Errorf("two hashes of same password are equal; want random salts")
		}
	})
}

func TestAPIKey(t *testing.T) {
	raw, hash, prefix := auth.NewAPIKey("pepper-one")
	if !strings.HasPrefix(raw, "gk_live_") {
		t.Fatalf("raw = %q, want gk_live_ prefix", raw)
	}
	if len(raw) != len("gk_live_")+32 {
		t.Fatalf("raw = %q, want 32 hex chars after prefix", raw)
	}
	for _, c := range raw[len("gk_live_"):] {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Fatalf("raw = %q, want lowercase hex", raw)
		}
	}
	if prefix != raw[len(raw)-8:] {
		t.Fatalf("prefix = %q, want last 8 of raw", prefix)
	}
	if hash != auth.HashAPIKey("pepper-one", raw) {
		t.Fatalf("hash not deterministic for same pepper+raw")
	}
	if auth.HashAPIKey("pepper-two", raw) == hash {
		t.Fatalf("different pepper produced same hash")
	}
	raw2, _, _ := auth.NewAPIKey("pepper-one")
	if raw2 == raw {
		t.Fatalf("two keys equal; want randomness")
	}
}

func TestSessionToken(t *testing.T) {
	raw, hash := auth.NewSessionToken()
	if len(raw) != 64 {
		t.Fatalf("raw len = %d, want 64 hex chars", len(raw))
	}
	for _, c := range raw {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Fatalf("raw = %q, want lowercase hex", raw)
		}
	}
	if hash != auth.HashSessionToken(raw) {
		t.Fatalf("hash not deterministic")
	}
	raw2, hash2 := auth.NewSessionToken()
	if raw2 == raw || hash2 == hash {
		t.Fatalf("two tokens equal; want randomness")
	}
}

func TestAuthenticateAPIKey(t *testing.T) {
	s := newTestStore(t)
	seedOrgUser(t, s, "o1", "u1", "active")
	a := &auth.Authenticator{Store: s, Pepper: "test-pepper"}

	raw, hash, prefix := auth.NewAPIKey("test-pepper")
	seedAPIKey(t, s, "k1", "o1", hash, prefix, 0, 0)

	got, err := a.AuthenticateAPIKey(raw)
	if err != nil {
		t.Fatalf("AuthenticateAPIKey valid: %v", err)
	}
	if got.OrgID != "o1" || got.Prefix != prefix {
		t.Fatalf("AuthenticateAPIKey = %+v, want org o1 prefix %q", got, prefix)
	}

	for name, mutate := range map[string]func() string{
		"unknown": func() string { return raw + "xx" },
	} {
		if _, err := a.AuthenticateAPIKey(mutate()); err == nil {
			t.Errorf("AuthenticateAPIKey(%s) = nil error, want error", name)
		}
	}

	rawRev, hashRev, prefixRev := auth.NewAPIKey("test-pepper")
	seedAPIKey(t, s, "k2", "o1", hashRev, prefixRev, 0, 1)
	if _, err := a.AuthenticateAPIKey(rawRev); err == nil {
		t.Errorf("AuthenticateAPIKey(revoked) = nil error, want error")
	}

	rawExp, hashExp, prefixExp := auth.NewAPIKey("test-pepper")
	seedAPIKey(t, s, "k3", "o1", hashExp, prefixExp, time.Now().Add(-time.Hour).Unix(), 0)
	if _, err := a.AuthenticateAPIKey(rawExp); err == nil {
		t.Errorf("AuthenticateAPIKey(expired) = nil error, want error")
	}
}

func TestMiddleware(t *testing.T) {
	type tokens struct {
		active, susp, exp, api, rev string
	}
	setup := func(t *testing.T) (*auth.Authenticator, tokens) {
		t.Helper()
		s := newTestStore(t)
		seedOrgUser(t, s, "o1", "u-active", "active")
		seedOrgUser(t, s, "o1", "u-suspended", "suspended")

		a := &auth.Authenticator{Store: s, Pepper: "test-pepper"}
		var tk tokens

		activeRaw, activeHash := auth.NewSessionToken()
		tk.active = activeRaw
		seedSession(t, s, "s-active", "o1", "u-active", activeHash, time.Now().Add(time.Hour).Unix())

		suspRaw, suspHash := auth.NewSessionToken()
		tk.susp = suspRaw
		seedSession(t, s, "s-susp", "o1", "u-suspended", suspHash, time.Now().Add(time.Hour).Unix())

		expRaw, expHash := auth.NewSessionToken()
		tk.exp = expRaw
		seedSession(t, s, "s-exp", "o1", "u-active", expHash, time.Now().Add(-time.Hour).Unix())

		apiRaw, apiHash, apiPrefix := auth.NewAPIKey("test-pepper")
		tk.api = apiRaw
		seedAPIKey(t, s, "k-ok", "o1", apiHash, apiPrefix, 0, 0)

		revRaw, revHash, revPrefix := auth.NewAPIKey("test-pepper")
		tk.rev = revRaw
		seedAPIKey(t, s, "k-rev", "o1", revHash, revPrefix, 0, 1)

		return a, tk
	}

	t.Run("401 no credentials", func(t *testing.T) {
		a, _ := setup(t)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		a.Middleware(okHandler(t, nil)).ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("code = %d, want 401", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), `"error"`) {
			t.Fatalf("body = %q, want JSON error", rec.Body.String())
		}
	})

	t.Run("200 session user", func(t *testing.T) {
		a, tk := setup(t)
		want := &auth.Identity{OrgID: "o1", UserID: "u-active", Kind: "session"}
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: "gk_session", Value: tk.active})
		rec := httptest.NewRecorder()
		a.Middleware(okHandler(t, want)).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("code = %d, want 200 (body %q)", rec.Code, rec.Body.String())
		}
	})

	t.Run("suspended user 401", func(t *testing.T) {
		a, tk := setup(t)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: "gk_session", Value: tk.susp})
		rec := httptest.NewRecorder()
		a.Middleware(okHandler(t, nil)).ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("code = %d, want 401", rec.Code)
		}
	})

	t.Run("expired session 401", func(t *testing.T) {
		a, tk := setup(t)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: "gk_session", Value: tk.exp})
		rec := httptest.NewRecorder()
		a.Middleware(okHandler(t, nil)).ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("code = %d, want 401", rec.Code)
		}
	})

	t.Run("bogus session 401", func(t *testing.T) {
		a, _ := setup(t)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: "gk_session", Value: "deadbeef"})
		rec := httptest.NewRecorder()
		a.Middleware(okHandler(t, nil)).ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("code = %d, want 401", rec.Code)
		}
	})

	t.Run("200 api key service identity", func(t *testing.T) {
		a, tk := setup(t)
		want := &auth.Identity{OrgID: "o1", UserID: "", Kind: "api_key"}
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-API-Key", tk.api)
		rec := httptest.NewRecorder()
		a.Middleware(okHandler(t, want)).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("code = %d, want 200 (body %q)", rec.Code, rec.Body.String())
		}
	})

	t.Run("revoked key 401", func(t *testing.T) {
		a, tk := setup(t)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-API-Key", tk.rev)
		rec := httptest.NewRecorder()
		a.Middleware(okHandler(t, nil)).ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("code = %d, want 401", rec.Code)
		}
	})

	t.Run("expired api key 401", func(t *testing.T) {
		s := newTestStore(t)
		seedOrgUser(t, s, "o1", "u-active", "active")
		a := &auth.Authenticator{Store: s, Pepper: "test-pepper"}
		raw, h, p := auth.NewAPIKey("test-pepper")
		seedAPIKey(t, s, "k-exp", "o1", h, p, time.Now().Add(-time.Hour).Unix(), 0)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-API-Key", raw)
		rec := httptest.NewRecorder()
		a.Middleware(okHandler(t, nil)).ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("code = %d, want 401", rec.Code)
		}
	})

	t.Run("session precedence over api key", func(t *testing.T) {
		a, tk := setup(t)
		want := &auth.Identity{OrgID: "o1", UserID: "u-active", Kind: "session"}
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: "gk_session", Value: tk.active})
		req.Header.Set("X-API-Key", tk.api)
		rec := httptest.NewRecorder()
		a.Middleware(okHandler(t, want)).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("code = %d, want 200", rec.Code)
		}
	})
}
