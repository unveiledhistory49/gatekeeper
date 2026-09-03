package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/unveiledhistory49/gatekeeper/internal/db"
)

func newID(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b[:])
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	pool, driver, err := db.Open("sqlite://:memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Migrate(pool); err != nil {
		pool.Close()
		t.Fatalf("migrate: %v", err)
	}
	// Clean shared-cache memory DB for isolation (child tables first).
	tables := []string{
		"idem", "review_items", "review_campaigns", "audit_log",
		"sessions", "api_keys", "oidc_links", "user_roles",
		"role_permissions", "users", "roles", "orgs",
	}
	for _, tb := range tables {
		if _, err := pool.Exec(`DELETE FROM "` + tb + `"`); err != nil {
			pool.Close()
			t.Fatalf("clean %s: %v", tb, err)
		}
	}
	t.Cleanup(func() { pool.Close() })
	return New(pool, driver)
}

func mustOrg(t *testing.T, s *Store, ctx context.Context) string {
	t.Helper()
	id := newID(t)
	if err := s.CreateOrg(ctx, id, "org-"+id[:8], 1000); err != nil {
		t.Fatalf("create org: %v", err)
	}
	return id
}

func TestUsers(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	org := mustOrg(t, s, ctx)

	u := User{ID: newID(t), OrgID: org, Email: "a@example.com", Name: "A", PasswordHash: "h", Status: "active", CreatedAt: 1001}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatalf("create user: %v", err)
	}

	t.Run("dup email conflict", func(t *testing.T) {
		dup := User{ID: newID(t), OrgID: org, Email: "a@example.com", Name: "A2", PasswordHash: "h", Status: "active", CreatedAt: 1002}
		if err := s.CreateUser(ctx, dup); !errors.Is(err, ErrConflict) {
			t.Fatalf("want ErrConflict, got %v", err)
		}
		// Same email in a different org is allowed.
		org2 := mustOrg(t, s, ctx)
		other := User{ID: newID(t), OrgID: org2, Email: "a@example.com", Name: "A3", PasswordHash: "h", Status: "active", CreatedAt: 1003}
		if err := s.CreateUser(ctx, other); err != nil {
			t.Fatalf("same email other org: %v", err)
		}
	})

	t.Run("status validation", func(t *testing.T) {
		cases := []struct {
			name    string
			status  string
			wantErr bool
		}{
			{"active ok", "active", false},
			{"suspended ok", "suspended", false},
			{"empty bad", "", true},
			{"deleted bad", "deleted", true},
			{"Active case bad", "Active", true},
			{"pending bad", "pending", true},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				err := s.SetUserStatus(ctx, org, u.ID, tc.status)
				if (err != nil) != tc.wantErr {
					t.Fatalf("status %q err=%v wantErr=%v", tc.status, err, tc.wantErr)
				}
			})
		}
		if err := s.SetUserStatus(ctx, org, "missing-user", "active"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("missing user: want ErrNotFound got %v", err)
		}
	})
}

func TestRolePerms(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	org := mustOrg(t, s, ctx)
	r := Role{ID: newID(t), OrgID: org, Name: "admin", Description: "d", CreatedAt: 1000}
	if err := s.CreateRole(ctx, r); err != nil {
		t.Fatalf("create role: %v", err)
	}
	if err := s.CreateRole(ctx, Role{ID: newID(t), OrgID: org, Name: "admin", CreatedAt: 1001}); !errors.Is(err, ErrConflict) {
		t.Fatalf("dup role name: want ErrConflict got %v", err)
	}

	if err := s.SetRolePermissions(ctx, r.ID, []string{"users:read", "users:write"}); err != nil {
		t.Fatalf("set perms: %v", err)
	}
	got, err := s.RolePermissions(ctx, r.ID)
	if err != nil {
		t.Fatalf("get perms: %v", err)
	}
	if len(got) != 2 || got[0] != "users:read" || got[1] != "users:write" {
		t.Fatalf("perms = %v", got)
	}
	// Replace semantics: old set must disappear.
	if err := s.SetRolePermissions(ctx, r.ID, []string{"orgs:read"}); err != nil {
		t.Fatalf("replace perms: %v", err)
	}
	got, _ = s.RolePermissions(ctx, r.ID)
	if len(got) != 1 || got[0] != "orgs:read" {
		t.Fatalf("after replace perms = %v", got)
	}
	// Empty clears.
	if err := s.SetRolePermissions(ctx, r.ID, nil); err != nil {
		t.Fatalf("clear perms: %v", err)
	}
	got, _ = s.RolePermissions(ctx, r.ID)
	if len(got) != 0 {
		t.Fatalf("after clear perms = %v", got)
	}

	invalid := []string{"", "Users:read", "users:Read", "a:b:c", "foo-bar", "has space", "ABC", "users:", ":read", "a b"}
	for _, p := range invalid {
		if err := s.SetRolePermissions(ctx, r.ID, []string{p}); err == nil {
			t.Fatalf("perm %q: want error got nil", p)
		}
	}
	valid := []string{"*", "a", "*:*", "a:*", "*:b", "abc:def"}
	if err := s.SetRolePermissions(ctx, r.ID, valid); err != nil {
		t.Fatalf("valid perms: %v", err)
	}
}

func TestSetUserRolesSameOrg(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	orgA := mustOrg(t, s, ctx)
	orgB := mustOrg(t, s, ctx)
	ua := User{ID: newID(t), OrgID: orgA, Email: "u@a.com", Name: "U", Status: "active", CreatedAt: 1000}
	if err := s.CreateUser(ctx, ua); err != nil {
		t.Fatal(err)
	}
	ra := Role{ID: newID(t), OrgID: orgA, Name: "ra", CreatedAt: 1000}
	rb := Role{ID: newID(t), OrgID: orgB, Name: "rb", CreatedAt: 1000}
	if err := s.CreateRole(ctx, ra); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateRole(ctx, rb); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRolePermissions(ctx, ra.ID, []string{"a:read"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRolePermissions(ctx, rb.ID, []string{"b:read"}); err != nil {
		t.Fatal(err)
	}

	if err := s.SetUserRoles(ctx, orgA, ua.ID, []string{ra.ID}); err != nil {
		t.Fatalf("same-org assign: %v", err)
	}
	if err := s.SetUserRoles(ctx, orgA, ua.ID, []string{rb.ID}); err == nil {
		t.Fatalf("cross-org assign: want error got nil")
	}
	if err := s.SetUserRoles(ctx, orgA, ua.ID, []string{"missing-role"}); err == nil {
		t.Fatalf("missing role: want error got nil")
	}
	roles, err := s.UserRoles(ctx, ua.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) != 1 || roles[0].ID != ra.ID {
		t.Fatalf("roles = %+v", roles)
	}
	perms, err := s.UserPermissions(ctx, ua.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(perms) != 1 || perms[0] != "a:read" {
		t.Fatalf("perms = %v", perms)
	}
}

func TestAuditChain(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	org := mustOrg(t, s, ctx)
	e1, err := s.AppendAudit(ctx, org, "alice", "create", "u1", "d1", 1000)
	if err != nil {
		t.Fatal(err)
	}
	if e1.PrevHash != "genesis" {
		t.Fatalf("first prev = %q", e1.PrevHash)
	}
	want := AuditHash(e1.PrevHash, org, "alice", "create", "u1", "d1", e1.Seq, 1000)
	if want != e1.Hash {
		t.Fatalf("hash mismatch")
	}
	e2, err := s.AppendAudit(ctx, org, "bob", "update", "u1", "d2", 1001)
	if err != nil {
		t.Fatal(err)
	}
	if e2.PrevHash != e1.Hash {
		t.Fatalf("chain prev mismatch: %q vs %q", e2.PrevHash, e1.Hash)
	}
	if e2.Seq != e1.Seq+1 {
		t.Fatalf("seq not consecutive: %d %d", e1.Seq, e2.Seq)
	}
	if err := s.VerifyAuditChain(ctx, org); err != nil {
		t.Fatalf("verify ok: %v", err)
	}
	list, err := s.ListAudit(ctx, org, 0, 10)
	if err != nil || len(list) != 2 {
		t.Fatalf("list = %v err=%v", len(list), err)
	}
	// Tamper with stored hash.
	if _, err := s.DB.ExecContext(ctx, s.q(`UPDATE audit_log SET hash = ? WHERE seq = ?`), "tampered", e2.Seq); err != nil {
		t.Fatal(err)
	}
	if err := s.VerifyAuditChain(ctx, org); err == nil {
		t.Fatalf("verify after tamper: want error got nil")
	}
}

func TestCampaigns(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	org := mustOrg(t, s, ctx)
	c := Campaign{ID: newID(t), OrgID: org, Name: "q1", Status: "open", CreatedBy: "admin", CreatedAt: 1000}
	if err := s.CreateCampaign(ctx, c); err != nil {
		t.Fatal(err)
	}
	item := ReviewItem{ID: newID(t), CampaignID: c.ID, UserID: newID(t), RoleID: newID(t), ReviewerID: "", Decision: "pending", DecidedAt: 0}
	if err := s.AddReviewItem(ctx, item); err != nil {
		t.Fatal(err)
	}

	t.Run("close blocked with pending", func(t *testing.T) {
		if err := s.CloseCampaign(ctx, org, c.ID, 2000); err == nil {
			t.Fatalf("want close blocked, got nil")
		}
	})

	t.Run("decide then double-decide fails", func(t *testing.T) {
		if err := s.DecideReviewItem(ctx, c.ID, item.ID, "rev1", "certified", 2001); err != nil {
			t.Fatalf("decide: %v", err)
		}
		if err := s.DecideReviewItem(ctx, c.ID, item.ID, "rev1", "revoked", 2002); err == nil {
			t.Fatalf("double decide: want error got nil")
		}
		if err := s.DecideReviewItem(ctx, c.ID, "missing", "rev1", "certified", 2003); !errors.Is(err, ErrNotFound) {
			t.Fatalf("missing item: want ErrNotFound got %v", err)
		}
		if err := s.DecideReviewItem(ctx, c.ID, item.ID, "rev1", "bogus", 2004); err == nil {
			t.Fatalf("bogus decision: want error got nil")
		}
	})

	t.Run("close succeeds after decided", func(t *testing.T) {
		if err := s.CloseCampaign(ctx, org, c.ID, 3000); err != nil {
			t.Fatalf("close: %v", err)
		}
		got, err := s.GetCampaign(ctx, org, c.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.Status != "closed" {
			t.Fatalf("status = %q", got.Status)
		}
	})
}

func TestIdempotency(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	org := mustOrg(t, s, ctx)
	if _, _, _, _, _, err := s.IdemGet(ctx, org, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: want ErrNotFound got %v", err)
	}
	if err := s.IdemPut(ctx, org, "k1", "POST", "/users", "req1", 201, `{"ok":true}`, 1000); err != nil {
		t.Fatal(err)
	}
	method, path, reqHash, status, body, err := s.IdemGet(ctx, org, "k1")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		got  any
		want any
	}{
		{"method", method, "POST"},
		{"path", path, "/users"},
		{"reqHash", reqHash, "req1"},
		{"status", status, 201},
		{"body", body, `{"ok":true}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Fatalf("got %v want %v", tc.got, tc.want)
			}
		})
	}
}

func TestRenameUser(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	org := mustOrg(t, s, ctx)
	uid := newID(t)
	if err := s.CreateUser(ctx, User{ID: uid, OrgID: org, Email: "a@x.io", Name: "A", PasswordHash: "h", CreatedAt: 1}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.RenameUser(ctx, org, uid, "B"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	u, err := s.GetUser(ctx, org, uid)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if u.Name != "B" {
		t.Fatalf("name = %q want B", u.Name)
	}
	if err := s.RenameUser(ctx, org, uid, ""); err == nil {
		t.Fatal("empty name should fail")
	}
	if err := s.RenameUser(ctx, org, "missing", "C"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing user err = %v, want ErrNotFound", err)
	}
	other := mustOrg(t, s, ctx)
	if err := s.RenameUser(ctx, other, uid, "C"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-org rename err = %v, want ErrNotFound", err)
	}
}
