package api_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/unveiledhistory49/gatekeeper/internal/api"
	"github.com/unveiledhistory49/gatekeeper/internal/auth"
	"github.com/unveiledhistory49/gatekeeper/internal/config"
	"github.com/unveiledhistory49/gatekeeper/internal/db"
	"github.com/unveiledhistory49/gatekeeper/internal/store"
)

// stubVerifier fakes OIDC verification without network. The callback path
// needs a live OAuth exchange, so tests only assert the OIDC-disabled 501s;
// this stub exists to prove Deps accepts any auth.Verifier implementation.
type stubVerifier struct{}

func (stubVerifier) Verify(ctx context.Context, raw string) (auth.Claims, error) {
	return auth.Claims{Subject: "sub-123", Email: "oidc@example.com", Name: "OIDC User"}, nil
}

var _ auth.Verifier = stubVerifier{}

type fixture struct {
	t       *testing.T
	handler http.Handler
	st      *store.Store
	orgID   string
	adminC  []*http.Cookie // admin session cookies
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	pool, driver, err := db.Open("sqlite://:memory:")
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if err := db.Migrate(pool); err != nil {
		t.Fatalf("db.Migrate: %v", err)
	}
	t.Cleanup(func() { _ = pool.Close() })
	st := store.New(pool, driver)
	now := time.Now().Unix()

	orgID := "o1"
	if err := st.CreateOrg(ctx, orgID, "Acme", now); err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	if err := st.CreateRole(ctx, store.Role{ID: "r-admin", OrgID: orgID, Name: "admin", Description: "Administrator", CreatedAt: now}); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if err := st.SetRolePermissions(ctx, "r-admin", []string{"*"}); err != nil {
		t.Fatalf("SetRolePermissions: %v", err)
	}
	ph, err := auth.HashPassword("admin-password-1")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := st.CreateUser(ctx, store.User{ID: "u-admin", OrgID: orgID, Email: "admin@example.com", Name: "Admin", PasswordHash: ph, Status: "active", CreatedAt: now}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := st.SetUserRoles(ctx, orgID, "u-admin", []string{"r-admin"}); err != nil {
		t.Fatalf("SetUserRoles: %v", err)
	}

	deps := api.Deps{
		Store: st,
		Auth:  &auth.Authenticator{Store: st, Pepper: "test-pepper"},
		Cfg:   config.Config{DatabaseURL: "sqlite://:memory:", Addr: ":0", Pepper: "test-pepper", SessionHours: 12},
	}
	h := api.NewRouter(deps)
	f := &fixture{t: t, handler: h, st: st, orgID: orgID}
	f.adminC = f.login("admin@example.com", "admin-password-1")
	return f
}

func (f *fixture) do(method, path string, body any, headers map[string]string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	f.t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			f.t.Fatalf("marshal: %v", err)
		}
		rdr = strings.NewReader(string(b))
	}
	req := httptest.NewRequest(method, path, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return m
}

func (f *fixture) login(email, password string) []*http.Cookie {
	f.t.Helper()
	rec := f.do("POST", "/v1/login", map[string]string{"org_id": f.orgID, "email": email, "password": password}, nil, nil)
	if rec.Code != http.StatusOK {
		f.t.Fatalf("login %s: code = %d (%s)", email, rec.Code, rec.Body.String())
	}
	m := decode(f.t, rec)
	if m["token"] == "" || m["expires_at"] == nil {
		f.t.Fatalf("login response missing token/expires_at: %s", rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		f.t.Fatalf("login did not set a cookie")
	}
	return cookies
}

func TestHealthz(t *testing.T) {
	f := newFixture(t)
	rec := f.do("GET", "/healthz", nil, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d", rec.Code)
	}
	m := decode(t, rec)
	if m["ok"] != true || m["version"] != "1.0.0" || m["time"] == nil {
		t.Fatalf("healthz = %s", rec.Body.String())
	}
}

func TestUnauthorized(t *testing.T) {
	f := newFixture(t)
	rec := f.do("GET", "/v1/me", nil, nil, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"error"`) {
		t.Fatalf("body = %q, want JSON error", rec.Body.String())
	}
}

func TestLoginAndMe(t *testing.T) {
	f := newFixture(t)
	// bad password
	rec := f.do("POST", "/v1/login", map[string]string{"org_id": f.orgID, "email": "admin@example.com", "password": "wrong-password-9"}, nil, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad password: code = %d, want 401", rec.Code)
	}
	// me over session
	rec = f.do("GET", "/v1/me", nil, nil, f.adminC)
	if rec.Code != http.StatusOK {
		t.Fatalf("me: code = %d (%s)", rec.Code, rec.Body.String())
	}
	m := decode(t, rec)
	if m["user_id"] != "u-admin" || m["org_id"] != f.orgID {
		t.Fatalf("me = %s", rec.Body.String())
	}
}

func TestRBACDeny(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	ph, _ := auth.HashPassword("plain-user-pass-1")
	if err := f.st.CreateUser(ctx, store.User{ID: "u-plain", OrgID: f.orgID, Email: "plain@example.com", Name: "Plain", PasswordHash: ph, Status: "active", CreatedAt: time.Now().Unix()}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	plainC := f.login("plain@example.com", "plain-user-pass-1")
	rec := f.do("POST", "/v1/users", map[string]string{"email": "x@example.com", "name": "X", "password": "some-password-1"}, nil, plainC)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403 (%s)", rec.Code, rec.Body.String())
	}
}

func TestUserRoleKeyFlow(t *testing.T) {
	f := newFixture(t)
	// create role
	rec := f.do("POST", "/v1/roles", map[string]any{"name": "editor", "description": "Editors", "permissions": []string{"users:read"}}, nil, f.adminC)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create role: code = %d (%s)", rec.Code, rec.Body.String())
	}
	roleID := decode(t, rec)["id"].(string)
	// set permissions
	rec = f.do("POST", "/v1/roles/"+roleID+"/permissions", map[string]any{"set": []string{"users:read", "users:write"}}, nil, f.adminC)
	if rec.Code != http.StatusOK {
		t.Fatalf("set perms: code = %d (%s)", rec.Code, rec.Body.String())
	}
	// list roles shows new perms
	rec = f.do("GET", "/v1/roles", nil, nil, f.adminC)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), roleID) {
		t.Fatalf("list roles: code = %d (%s)", rec.Code, rec.Body.String())
	}
	// create user with role
	rec = f.do("POST", "/v1/users", map[string]any{"email": "ed@example.com", "name": "Ed", "password": "editor-password-1", "role_ids": []string{roleID}}, nil, f.adminC)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create user: code = %d (%s)", rec.Code, rec.Body.String())
	}
	userID := decode(t, rec)["id"].(string)
	// get user shows role
	rec = f.do("GET", "/v1/users/"+userID, nil, nil, f.adminC)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), roleID) {
		t.Fatalf("get user: code = %d (%s)", rec.Code, rec.Body.String())
	}
	// assign roles (idempotent set)
	rec = f.do("POST", "/v1/users/"+userID+"/roles", map[string]any{"role_ids": []string{roleID}}, nil, f.adminC)
	if rec.Code != http.StatusOK {
		t.Fatalf("set roles: code = %d (%s)", rec.Code, rec.Body.String())
	}
	// suspend + reactivate via PATCH
	rec = f.do("PATCH", "/v1/users/"+userID, map[string]string{"status": "suspended"}, nil, f.adminC)
	if rec.Code != http.StatusOK {
		t.Fatalf("suspend: code = %d (%s)", rec.Code, rec.Body.String())
	}
	rec = f.do("POST", "/v1/login", map[string]string{"org_id": f.orgID, "email": "ed@example.com", "password": "editor-password-1"}, nil, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("suspended login: code = %d, want 401", rec.Code)
	}
	rec = f.do("PATCH", "/v1/users/"+userID, map[string]string{"status": "active"}, nil, f.adminC)
	if rec.Code != http.StatusOK {
		t.Fatalf("reactivate: code = %d (%s)", rec.Code, rec.Body.String())
	}
	// create api key (raw returned once)
	rec = f.do("POST", "/v1/api-keys", map[string]any{"name": "ci"}, nil, f.adminC)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create key: code = %d (%s)", rec.Code, rec.Body.String())
	}
	km := decode(t, rec)
	raw, _ := km["api_key"].(string)
	keyID, _ := km["id"].(string)
	if !strings.HasPrefix(raw, "gk_live_") || keyID == "" {
		t.Fatalf("key response = %s", rec.Body.String())
	}
	// list never exposes hashes
	rec = f.do("GET", "/v1/api-keys", nil, nil, f.adminC)
	if rec.Code != http.StatusOK {
		t.Fatalf("list keys: code = %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "key_hash") || strings.Contains(rec.Body.String(), raw) {
		t.Fatalf("key hash leaked: %s", rec.Body.String())
	}
	// raw key authenticates as api_key identity on /v1/me
	rec = f.do("GET", "/v1/me", nil, map[string]string{"X-API-Key": raw}, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "api_key") {
		t.Fatalf("me via api key: code = %d (%s)", rec.Code, rec.Body.String())
	}
	// revoke
	rec = f.do("POST", "/v1/api-keys/"+keyID+"/revoke", nil, nil, f.adminC)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke: code = %d (%s)", rec.Code, rec.Body.String())
	}
	rec = f.do("GET", "/v1/me", nil, map[string]string{"X-API-Key": raw}, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked key: code = %d, want 401", rec.Code)
	}
	// logout ends the admin session
	rec = f.do("POST", "/v1/logout", nil, nil, f.adminC)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("logout: code = %d, want 204", rec.Code)
	}
	rec = f.do("GET", "/v1/me", nil, nil, f.adminC)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("post-logout me: code = %d, want 401", rec.Code)
	}
	// re-login for subsequent tests using this fixture is unnecessary (fresh fixtures elsewhere)
	f.adminC = f.login("admin@example.com", "admin-password-1")
}

func TestReviewCampaign(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	now := time.Now().Unix()
	for _, r := range []struct{ id, name string }{{"r-one", "one"}, {"r-two", "two"}} {
		if err := f.st.CreateRole(ctx, store.Role{ID: r.id, OrgID: f.orgID, Name: r.name, CreatedAt: now}); err != nil {
			t.Fatalf("CreateRole: %v", err)
		}
	}
	ph, _ := auth.HashPassword("review-user-pass-1")
	if err := f.st.CreateUser(ctx, store.User{ID: "u-bob", OrgID: f.orgID, Email: "bob@example.com", Name: "Bob", PasswordHash: ph, Status: "active", CreatedAt: now}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := f.st.SetUserRoles(ctx, f.orgID, "u-bob", []string{"r-one", "r-two"}); err != nil {
		t.Fatalf("SetUserRoles: %v", err)
	}
	// create campaign → auto items for every user_role pair
	rec := f.do("POST", "/v1/reviews/campaigns", map[string]string{"name": "Q1 review"}, nil, f.adminC)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create campaign: code = %d (%s)", rec.Code, rec.Body.String())
	}
	campID := decode(t, rec)["id"].(string)
	rec = f.do("GET", "/v1/reviews/campaigns/"+campID+"/items", nil, nil, f.adminC)
	if rec.Code != http.StatusOK {
		t.Fatalf("list items: code = %d", rec.Code)
	}
	var items struct {
		Items []store.ReviewItem `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &items); err != nil {
		t.Fatalf("items decode: %v", err)
	}
	byPair := map[string]string{}
	for _, it := range items.Items {
		byPair[it.UserID+"/"+it.RoleID] = it.ID
		if it.Decision != "pending" {
			t.Fatalf("item %s not pending", it.ID)
		}
	}
	certID, ok := byPair["u-bob/r-one"]
	revID, ok2 := byPair["u-bob/r-two"]
	if !ok || !ok2 {
		t.Fatalf("auto items missing bob pairs: %v", byPair)
	}
	// certify one
	rec = f.do("POST", "/v1/reviews/items/"+certID+"/decide", map[string]string{"decision": "certified"}, nil, f.adminC)
	if rec.Code != http.StatusOK {
		t.Fatalf("certify: code = %d (%s)", rec.Code, rec.Body.String())
	}
	// double decide → conflict
	rec = f.do("POST", "/v1/reviews/items/"+certID+"/decide", map[string]string{"decision": "certified"}, nil, f.adminC)
	if rec.Code != http.StatusConflict {
		t.Fatalf("re-decide: code = %d, want 409", rec.Code)
	}
	// revoke the other → role removed
	rec = f.do("POST", "/v1/reviews/items/"+revID+"/decide", map[string]string{"decision": "revoked"}, nil, f.adminC)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke: code = %d (%s)", rec.Code, rec.Body.String())
	}
	roles, err := f.st.UserRoles(ctx, "u-bob")
	if err != nil {
		t.Fatalf("UserRoles: %v", err)
	}
	for _, r := range roles {
		if r.ID == "r-two" {
			t.Fatalf("revoked role r-two still assigned: %+v", roles)
		}
	}
	// close requires all decided: certify the rest
	rec = f.do("GET", "/v1/reviews/campaigns/"+campID+"/items", nil, nil, f.adminC)
	var cur struct {
		Items []store.ReviewItem `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &cur); err != nil {
		t.Fatalf("items decode: %v", err)
	}
	for _, it := range cur.Items {
		if it.Decision == "pending" {
			rec := f.do("POST", "/v1/reviews/items/"+it.ID+"/decide", map[string]string{"decision": "certified"}, nil, f.adminC)
			if rec.Code != http.StatusOK {
				t.Fatalf("certify %s: code = %d (%s)", it.ID, rec.Code, rec.Body.String())
			}
		}
	}
	rec = f.do("POST", "/v1/reviews/campaigns/"+campID+"/close", nil, nil, f.adminC)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "closed") {
		t.Fatalf("close: code = %d (%s)", rec.Code, rec.Body.String())
	}
}

func TestAudit(t *testing.T) {
	f := newFixture(t)
	rec := f.do("GET", "/v1/audit?since_seq=0&limit=50", nil, nil, f.adminC)
	if rec.Code != http.StatusOK {
		t.Fatalf("list audit: code = %d (%s)", rec.Code, rec.Body.String())
	}
	var list struct {
		Entries []store.AuditEntry `json:"entries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("audit decode: %v", err)
	}
	if len(list.Entries) == 0 {
		t.Fatalf("expected audit entries, got none")
	}
	rec = f.do("GET", "/v1/audit/verify", nil, nil, f.adminC)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ok":true`) {
		t.Fatalf("verify: code = %d (%s)", rec.Code, rec.Body.String())
	}
}

func TestIdempotentUserCreate(t *testing.T) {
	f := newFixture(t)
	body := map[string]any{"email": "idem@example.com", "name": "Idem", "password": "idempotent-pass-1"}
	h := map[string]string{"Idempotency-Key": "test-key-0001"}
	rec1 := f.do("POST", "/v1/users", body, h, f.adminC)
	rec2 := f.do("POST", "/v1/users", body, h, f.adminC)
	if rec1.Code != http.StatusCreated || rec2.Code != http.StatusCreated {
		t.Fatalf("codes = %d,%d (%s) (%s)", rec1.Code, rec2.Code, rec1.Body.String(), rec2.Body.String())
	}
	if rec1.Body.String() != rec2.Body.String() {
		t.Fatalf("replay mismatch:\n%s\n%s", rec1.Body.String(), rec2.Body.String())
	}
	// same key, different body → 409
	rec3 := f.do("POST", "/v1/users", map[string]any{"email": "other@example.com", "name": "Other", "password": "idempotent-pass-2"}, h, f.adminC)
	if rec3.Code != http.StatusConflict {
		t.Fatalf("mismatch: code = %d, want 409 (%s)", rec3.Code, rec3.Body.String())
	}
	// invalid key → 422
	rec4 := f.do("POST", "/v1/users", body, map[string]string{"Idempotency-Key": "short"}, f.adminC)
	if rec4.Code != 422 {
		t.Fatalf("short key: code = %d, want 422", rec4.Code)
	}
	// only one user was created by the replay pair
	users, err := f.st.ListUsers(context.Background(), f.orgID, 100, 0)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	n := 0
	for _, u := range users {
		if u.Email == "idem@example.com" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("idem@example.com count = %d, want 1", n)
	}
}

func TestSCIM(t *testing.T) {
	f := newFixture(t)
	rec := f.do("POST", "/scim/v2/Users", map[string]string{"userName": "scim@example.com", "displayName": "Scim", "password": "scim-password-1"}, map[string]string{"Idempotency-Key": "scim-key-0001"}, f.adminC)
	if rec.Code != http.StatusCreated {
		t.Fatalf("scim create: code = %d (%s)", rec.Code, rec.Body.String())
	}
	id := decode(t, rec)["id"].(string)
	rec = f.do("GET", "/scim/v2/Users?startIndex=1&count=100", nil, nil, f.adminC)
	if rec.Code != http.StatusOK {
		t.Fatalf("scim list: code = %d", rec.Code)
	}
	var list struct {
		Schemas      []string `json:"schemas"`
		TotalResults int      `json:"totalResults"`
		StartIndex   int      `json:"startIndex"`
		Resources    []struct {
			ID       string `json:"id"`
			UserName string `json:"userName"`
		} `json:"Resources"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("scim decode: %v", err)
	}
	if len(list.Schemas) == 0 || !strings.Contains(list.Schemas[0], "ListResponse") {
		t.Fatalf("scim envelope = %s", rec.Body.String())
	}
	found := false
	for _, r := range list.Resources {
		if r.ID == id && r.UserName == "scim@example.com" {
			found = true
		}
	}
	if !found {
		t.Fatalf("created user missing from SCIM list: %s", rec.Body.String())
	}
	rec = f.do("GET", "/scim/v2/Users/"+id, nil, nil, f.adminC)
	if rec.Code != http.StatusOK {
		t.Fatalf("scim get: code = %d", rec.Code)
	}
}

func TestOIDCDisabled(t *testing.T) {
	f := newFixture(t)
	rec := f.do("GET", "/v1/oidc/login", nil, nil, nil)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("oidc login: code = %d, want 501 (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"error"`) {
		t.Fatalf("body = %q, want JSON error", rec.Body.String())
	}
	rec = f.do("GET", "/v1/oidc/callback?code=x&state=y", nil, nil, nil)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("oidc callback: code = %d, want 501", rec.Code)
	}
	// Even with a verifier plugged in, a disabled config gates first.
	deps := api.Deps{
		Store: f.st, Auth: &auth.Authenticator{Store: f.st, Pepper: "test-pepper"},
		Cfg:  config.Config{Pepper: "test-pepper"},
		OIDC: stubVerifier{},
	}
	rec2 := httptest.NewRecorder()
	api.NewRouter(deps).ServeHTTP(rec2, httptest.NewRequest("GET", "/v1/oidc/login", nil))
	if rec2.Code != http.StatusNotImplemented {
		t.Fatalf("oidc login with stub: code = %d, want 501", rec2.Code)
	}
}
