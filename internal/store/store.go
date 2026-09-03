package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/unveiledhistory49/gatekeeper/internal/db"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
)

type Store struct {
	DB     *sql.DB
	Driver string
}

func New(database *sql.DB, driver string) *Store {
	return &Store{DB: database, Driver: driver}
}

type Org struct {
	ID        string
	Name      string
	CreatedAt int64
}

type User struct {
	ID           string
	OrgID        string
	Email        string
	Name         string
	PasswordHash string
	Status       string
	CreatedAt    int64
}

type Role struct {
	ID          string
	OrgID       string
	Name        string
	Description string
	CreatedAt   int64
}

type APIKey struct {
	ID        string
	OrgID     string
	Name      string
	KeyHash   string
	Prefix    string
	ExpiresAt int64
	Revoked   bool
	CreatedAt int64
}

type Session struct {
	ID        string
	OrgID     string
	UserID    string
	TokenHash string
	CreatedAt int64
	ExpiresAt int64
}

type AuditEntry struct {
	Seq       int64  `json:"seq"`
	OrgID     string `json:"org_id"`
	Actor     string `json:"actor"`
	Action    string `json:"action"`
	Target    string `json:"target"`
	Detail    string `json:"detail"`
	PrevHash  string `json:"prev_hash"`
	Hash      string `json:"hash"`
	CreatedAt int64  `json:"created_at"`
}

type Campaign struct {
	ID        string `json:"id"`
	OrgID     string `json:"org_id"`
	Name      string `json:"name"`
	Status    string `json:"status"`
	CreatedBy string `json:"created_by"`
	CreatedAt int64  `json:"created_at"`
	ClosedAt  int64  `json:"closed_at"`
}

type ReviewItem struct {
	ID         string `json:"id"`
	CampaignID string `json:"campaign_id"`
	UserID     string `json:"user_id"`
	RoleID     string `json:"role_id"`
	ReviewerID string `json:"reviewer_id"`
	Decision   string `json:"decision"`
	DecidedAt  int64  `json:"decided_at"`
}

func (s *Store) q(query string) string {
	return db.Rebind(s.Driver, query)
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint") ||
		strings.Contains(msg, "duplicate key") ||
		strings.Contains(msg, "23505")
}

func validPerm(p string) bool {
	if p == "" {
		return false
	}
	parts := strings.Split(p, ":")
	if len(parts) < 1 || len(parts) > 2 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, r := range part {
			if r == '*' {
				continue
			}
			if r < 'a' || r > 'z' {
				return false
			}
		}
	}
	return true
}

func (s *Store) CreateOrg(ctx context.Context, id, name string, now int64) error {
	_, err := s.DB.ExecContext(ctx, s.q(`INSERT INTO orgs (id, name, created_at) VALUES (?, ?, ?)`), id, name, now)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("create org: %w", ErrConflict)
		}
		return err
	}
	return nil
}

func (s *Store) GetOrg(ctx context.Context, id string) (Org, error) {
	var o Org
	err := s.DB.QueryRowContext(ctx, s.q(`SELECT id, name, created_at FROM orgs WHERE id = ?`), id).Scan(&o.ID, &o.Name, &o.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Org{}, fmt.Errorf("get org: %w", ErrNotFound)
		}
		return Org{}, err
	}
	return o, nil
}

func (s *Store) CreateUser(ctx context.Context, u User) error {
	_, err := s.DB.ExecContext(ctx, s.q(`INSERT INTO users (id, org_id, email, name, password_hash, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`),
		u.ID, u.OrgID, u.Email, u.Name, u.PasswordHash, u.Status, u.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("create user: %w", ErrConflict)
		}
		return err
	}
	return nil
}

func (s *Store) GetUser(ctx context.Context, orgID, userID string) (User, error) {
	var u User
	err := s.DB.QueryRowContext(ctx, s.q(`SELECT id, org_id, email, name, password_hash, status, created_at FROM users WHERE id = ? AND org_id = ?`), userID, orgID).Scan(
		&u.ID, &u.OrgID, &u.Email, &u.Name, &u.PasswordHash, &u.Status, &u.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, fmt.Errorf("get user: %w", ErrNotFound)
		}
		return User{}, err
	}
	return u, nil
}

func (s *Store) GetUserByEmail(ctx context.Context, orgID, email string) (User, error) {
	var u User
	err := s.DB.QueryRowContext(ctx, s.q(`SELECT id, org_id, email, name, password_hash, status, created_at FROM users WHERE org_id = ? AND email = ?`), orgID, email).Scan(
		&u.ID, &u.OrgID, &u.Email, &u.Name, &u.PasswordHash, &u.Status, &u.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, fmt.Errorf("get user by email: %w", ErrNotFound)
		}
		return User{}, err
	}
	return u, nil
}

func (s *Store) ListUsers(ctx context.Context, orgID string, limit, offset int) ([]User, error) {
	if limit <= 0 {
		limit = 1<<31 - 1
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.DB.QueryContext(ctx, s.q(`SELECT id, org_id, email, name, password_hash, status, created_at FROM users WHERE org_id = ? ORDER BY created_at, id LIMIT ? OFFSET ?`), orgID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.OrgID, &u.Email, &u.Name, &u.PasswordHash, &u.Status, &u.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) SetUserStatus(ctx context.Context, orgID, userID, status string) error {
	if status != "active" && status != "suspended" {
		return fmt.Errorf("invalid status %q: must be active or suspended", status)
	}
	res, err := s.DB.ExecContext(ctx, s.q(`UPDATE users SET status = ? WHERE id = ? AND org_id = ?`), status, userID, orgID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("set user status: %w", ErrNotFound)
	}
	return nil
}

func (s *Store) RenameUser(ctx context.Context, orgID, userID, name string) error {
	if name == "" {
		return fmt.Errorf("name must not be empty")
	}
	res, err := s.DB.ExecContext(ctx, s.q(`UPDATE users SET name = ? WHERE id = ? AND org_id = ?`), name, userID, orgID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("rename user: %w", ErrNotFound)
	}
	return nil
}

func (s *Store) CreateRole(ctx context.Context, r Role) error {
	_, err := s.DB.ExecContext(ctx, s.q(`INSERT INTO roles (id, org_id, name, description, created_at) VALUES (?, ?, ?, ?, ?)`),
		r.ID, r.OrgID, r.Name, r.Description, r.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("create role: %w", ErrConflict)
		}
		return err
	}
	return nil
}

func (s *Store) GetRole(ctx context.Context, orgID, roleID string) (Role, error) {
	var r Role
	err := s.DB.QueryRowContext(ctx, s.q(`SELECT id, org_id, name, description, created_at FROM roles WHERE id = ? AND org_id = ?`), roleID, orgID).Scan(
		&r.ID, &r.OrgID, &r.Name, &r.Description, &r.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Role{}, fmt.Errorf("get role: %w", ErrNotFound)
		}
		return Role{}, err
	}
	return r, nil
}

func (s *Store) ListRoles(ctx context.Context, orgID string) ([]Role, error) {
	rows, err := s.DB.QueryContext(ctx, s.q(`SELECT id, org_id, name, description, created_at FROM roles WHERE org_id = ? ORDER BY name`), orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Role{}
	for rows.Next() {
		var r Role
		if err := rows.Scan(&r.ID, &r.OrgID, &r.Name, &r.Description, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) SetRolePermissions(ctx context.Context, roleID string, perms []string) error {
	for _, p := range perms {
		if !validPerm(p) {
			return fmt.Errorf("invalid permission %q", p)
		}
	}
	seen := map[string]struct{}{}
	dedup := make([]string, 0, len(perms))
	for _, p := range perms {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		dedup = append(dedup, p)
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, s.q(`DELETE FROM role_permissions WHERE role_id = ?`), roleID); err != nil {
		return err
	}
	for _, p := range dedup {
		if _, err := tx.ExecContext(ctx, s.q(`INSERT INTO role_permissions (role_id, permission) VALUES (?, ?)`), roleID, p); err != nil {
			if isUniqueViolation(err) {
				return fmt.Errorf("set role permissions: %w", ErrConflict)
			}
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func (s *Store) RolePermissions(ctx context.Context, roleID string) ([]string, error) {
	rows, err := s.DB.QueryContext(ctx, s.q(`SELECT permission FROM role_permissions WHERE role_id = ? ORDER BY permission`), roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) SetUserRoles(ctx context.Context, orgID, userID string, roleIDs []string) error {
	seen := map[string]struct{}{}
	dedup := make([]string, 0, len(roleIDs))
	for _, r := range roleIDs {
		if _, ok := seen[r]; ok {
			continue
		}
		seen[r] = struct{}{}
		dedup = append(dedup, r)
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var userOrg string
	err = tx.QueryRowContext(ctx, s.q(`SELECT org_id FROM users WHERE id = ?`), userID).Scan(&userOrg)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("set user roles: user: %w", ErrNotFound)
		}
		return err
	}
	if userOrg != orgID {
		return fmt.Errorf("set user roles: user %q does not belong to org %q", userID, orgID)
	}
	for _, rid := range dedup {
		var roleOrg string
		err := tx.QueryRowContext(ctx, s.q(`SELECT org_id FROM roles WHERE id = ?`), rid).Scan(&roleOrg)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("set user roles: role %q: %w", rid, ErrNotFound)
			}
			return err
		}
		if roleOrg != orgID {
			return fmt.Errorf("set user roles: role %q does not belong to org %q", rid, orgID)
		}
	}
	if _, err := tx.ExecContext(ctx, s.q(`DELETE FROM user_roles WHERE user_id = ?`), userID); err != nil {
		return err
	}
	for _, rid := range dedup {
		if _, err := tx.ExecContext(ctx, s.q(`INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)`), userID, rid); err != nil {
			if isUniqueViolation(err) {
				return fmt.Errorf("set user roles: %w", ErrConflict)
			}
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func (s *Store) UserRoles(ctx context.Context, userID string) ([]Role, error) {
	rows, err := s.DB.QueryContext(ctx, s.q(`SELECT r.id, r.org_id, r.name, r.description, r.created_at FROM roles r JOIN user_roles ur ON ur.role_id = r.id WHERE ur.user_id = ? ORDER BY r.name`), userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Role{}
	for rows.Next() {
		var r Role
		if err := rows.Scan(&r.ID, &r.OrgID, &r.Name, &r.Description, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) UserPermissions(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.DB.QueryContext(ctx, s.q(`SELECT DISTINCT rp.permission FROM role_permissions rp JOIN user_roles ur ON ur.role_id = rp.role_id WHERE ur.user_id = ? ORDER BY rp.permission`), userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) CreateAPIKey(ctx context.Context, k APIKey) error {
	revoked := 0
	if k.Revoked {
		revoked = 1
	}
	_, err := s.DB.ExecContext(ctx, s.q(`INSERT INTO api_keys (id, org_id, name, key_hash, prefix, expires_at, revoked, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`),
		k.ID, k.OrgID, k.Name, k.KeyHash, k.Prefix, k.ExpiresAt, revoked, k.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("create api key: %w", ErrConflict)
		}
		return err
	}
	return nil
}

func (s *Store) GetAPIKeyByHash(ctx context.Context, hash string) (APIKey, error) {
	var k APIKey
	var revoked int
	err := s.DB.QueryRowContext(ctx, s.q(`SELECT id, org_id, name, key_hash, prefix, expires_at, revoked, created_at FROM api_keys WHERE key_hash = ?`), hash).Scan(
		&k.ID, &k.OrgID, &k.Name, &k.KeyHash, &k.Prefix, &k.ExpiresAt, &revoked, &k.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return APIKey{}, fmt.Errorf("get api key: %w", ErrNotFound)
		}
		return APIKey{}, err
	}
	k.Revoked = revoked != 0
	return k, nil
}

func (s *Store) ListAPIKeys(ctx context.Context, orgID string) ([]APIKey, error) {
	rows, err := s.DB.QueryContext(ctx, s.q(`SELECT id, org_id, name, key_hash, prefix, expires_at, revoked, created_at FROM api_keys WHERE org_id = ? ORDER BY created_at, id`), orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []APIKey{}
	for rows.Next() {
		var k APIKey
		var revoked int
		if err := rows.Scan(&k.ID, &k.OrgID, &k.Name, &k.KeyHash, &k.Prefix, &k.ExpiresAt, &revoked, &k.CreatedAt); err != nil {
			return nil, err
		}
		k.Revoked = revoked != 0
		out = append(out, k)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) RevokeAPIKey(ctx context.Context, orgID, keyID string) error {
	res, err := s.DB.ExecContext(ctx, s.q(`UPDATE api_keys SET revoked = 1 WHERE id = ? AND org_id = ?`), keyID, orgID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("revoke api key: %w", ErrNotFound)
	}
	return nil
}

func (s *Store) CreateSession(ctx context.Context, se Session) error {
	_, err := s.DB.ExecContext(ctx, s.q(`INSERT INTO sessions (id, org_id, user_id, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)`),
		se.ID, se.OrgID, se.UserID, se.TokenHash, se.CreatedAt, se.ExpiresAt)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("create session: %w", ErrConflict)
		}
		return err
	}
	return nil
}

func (s *Store) GetSessionByHash(ctx context.Context, hash string) (Session, error) {
	var se Session
	err := s.DB.QueryRowContext(ctx, s.q(`SELECT id, org_id, user_id, token_hash, created_at, expires_at FROM sessions WHERE token_hash = ?`), hash).Scan(
		&se.ID, &se.OrgID, &se.UserID, &se.TokenHash, &se.CreatedAt, &se.ExpiresAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Session{}, fmt.Errorf("get session: %w", ErrNotFound)
		}
		return Session{}, err
	}
	return se, nil
}

func (s *Store) DeleteSession(ctx context.Context, id string) error {
	res, err := s.DB.ExecContext(ctx, s.q(`DELETE FROM sessions WHERE id = ?`), id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("delete session: %w", ErrNotFound)
	}
	return nil
}

func (s *Store) LinkOIDC(ctx context.Context, orgID, provider, subject, userID string, now int64) error {
	_, err := s.DB.ExecContext(ctx, s.q(`INSERT INTO oidc_links (org_id, provider, subject, user_id, created_at) VALUES (?, ?, ?, ?, ?)`),
		orgID, provider, subject, userID, now)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("link oidc: %w", ErrConflict)
		}
		return err
	}
	return nil
}

func (s *Store) GetOIDCUser(ctx context.Context, orgID, provider, subject string) (User, error) {
	var u User
	err := s.DB.QueryRowContext(ctx, s.q(`SELECT u.id, u.org_id, u.email, u.name, u.password_hash, u.status, u.created_at FROM users u JOIN oidc_links o ON o.user_id = u.id WHERE o.org_id = ? AND o.provider = ? AND o.subject = ?`),
		orgID, provider, subject).Scan(&u.ID, &u.OrgID, &u.Email, &u.Name, &u.PasswordHash, &u.Status, &u.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, fmt.Errorf("get oidc user: %w", ErrNotFound)
		}
		return User{}, err
	}
	return u, nil
}

func AuditHash(prev, orgID, actor, action, target, detail string, seq, now int64) string {
	raw := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s\n%d\n%d", prev, orgID, actor, action, target, detail, seq, now)
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func (s *Store) AppendAudit(ctx context.Context, orgID, actor, action, target, detail string, now int64) (AuditEntry, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return AuditEntry{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var maxSeq sql.NullInt64
	if err := tx.QueryRowContext(ctx, s.q(`SELECT COALESCE(MAX(seq), 0) FROM audit_log`)).Scan(&maxSeq); err != nil {
		return AuditEntry{}, err
	}
	next := int64(1)
	if maxSeq.Valid {
		next = maxSeq.Int64 + 1
	}
	prev := "genesis"
	var orgTip sql.NullString
	if err := tx.QueryRowContext(ctx, s.q(`SELECT hash FROM audit_log WHERE org_id = ? ORDER BY seq DESC LIMIT 1`), orgID).Scan(&orgTip); err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return AuditEntry{}, err
		}
		prev = "genesis"
	} else if orgTip.Valid {
		prev = orgTip.String
	} else {
		prev = "genesis"
	}
	h := AuditHash(prev, orgID, actor, action, target, detail, next, now)
	if _, err := tx.ExecContext(ctx, s.q(`INSERT INTO audit_log (seq, org_id, actor, action, target, detail, prev_hash, hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		next, orgID, actor, action, target, detail, prev, h, now); err != nil {
		if isUniqueViolation(err) {
			return AuditEntry{}, fmt.Errorf("append audit: %w", ErrConflict)
		}
		return AuditEntry{}, err
	}
	if err := tx.Commit(); err != nil {
		return AuditEntry{}, err
	}
	return AuditEntry{Seq: next, OrgID: orgID, Actor: actor, Action: action, Target: target, Detail: detail, PrevHash: prev, Hash: h, CreatedAt: now}, nil
}

func (s *Store) ListAudit(ctx context.Context, orgID string, sinceSeq int64, limit int) ([]AuditEntry, error) {
	base := `SELECT seq, org_id, actor, action, target, detail, prev_hash, hash, created_at FROM audit_log WHERE org_id = ? AND seq > ? ORDER BY seq`
	args := []any{orgID, sinceSeq}
	if limit > 0 {
		base += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := s.DB.QueryContext(ctx, s.q(base), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.Seq, &e.OrgID, &e.Actor, &e.Action, &e.Target, &e.Detail, &e.PrevHash, &e.Hash, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) VerifyAuditChain(ctx context.Context, orgID string) error {
	rows, err := s.DB.QueryContext(ctx, s.q(`SELECT seq, actor, action, target, detail, prev_hash, hash, created_at FROM audit_log WHERE org_id = ? ORDER BY seq`), orgID)
	if err != nil {
		return err
	}
	defer rows.Close()
	type rec struct {
		seq      int64
		actor    string
		action   string
		target   string
		detail   string
		prevHash string
		hash     string
		at       int64
	}
	var recs []rec
	for rows.Next() {
		var r rec
		if err := rows.Scan(&r.seq, &r.actor, &r.action, &r.target, &r.detail, &r.prevHash, &r.hash, &r.at); err != nil {
			return err
		}
		recs = append(recs, r)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(recs) == 0 {
		return nil
	}
	if recs[0].prevHash != "genesis" {
		return fmt.Errorf("audit chain broken at seq %d: first prev_hash = %q, want %q", recs[0].seq, recs[0].prevHash, "genesis")
	}
	for i, r := range recs {
		if i > 0 && r.seq != recs[i-1].seq+1 {
			return fmt.Errorf("audit chain gap for org %q: expected seq %d, got %d", orgID, recs[i-1].seq+1, r.seq)
		}
		want := AuditHash(r.prevHash, orgID, r.actor, r.action, r.target, r.detail, r.seq, r.at)
		if want != r.hash {
			return fmt.Errorf("audit chain tamper at seq %d: hash mismatch (want %s, got %s)", r.seq, want, r.hash)
		}
		if i > 0 && r.prevHash != recs[i-1].hash {
			return fmt.Errorf("audit chain broken at seq %d: prev_hash does not match hash of seq %d", r.seq, recs[i-1].seq)
		}
	}
	return nil
}

func (s *Store) CreateCampaign(ctx context.Context, c Campaign) error {
	_, err := s.DB.ExecContext(ctx, s.q(`INSERT INTO review_campaigns (id, org_id, name, status, created_by, created_at, closed_at) VALUES (?, ?, ?, ?, ?, ?, ?)`),
		c.ID, c.OrgID, c.Name, c.Status, c.CreatedBy, c.CreatedAt, c.ClosedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("create campaign: %w", ErrConflict)
		}
		return err
	}
	return nil
}

func (s *Store) GetCampaign(ctx context.Context, orgID, id string) (Campaign, error) {
	var c Campaign
	err := s.DB.QueryRowContext(ctx, s.q(`SELECT id, org_id, name, status, created_by, created_at, closed_at FROM review_campaigns WHERE id = ? AND org_id = ?`), id, orgID).Scan(
		&c.ID, &c.OrgID, &c.Name, &c.Status, &c.CreatedBy, &c.CreatedAt, &c.ClosedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Campaign{}, fmt.Errorf("get campaign: %w", ErrNotFound)
		}
		return Campaign{}, err
	}
	return c, nil
}

func (s *Store) ListCampaigns(ctx context.Context, orgID string) ([]Campaign, error) {
	rows, err := s.DB.QueryContext(ctx, s.q(`SELECT id, org_id, name, status, created_by, created_at, closed_at FROM review_campaigns WHERE org_id = ? ORDER BY created_at, id`), orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Campaign{}
	for rows.Next() {
		var c Campaign
		if err := rows.Scan(&c.ID, &c.OrgID, &c.Name, &c.Status, &c.CreatedBy, &c.CreatedAt, &c.ClosedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) AddReviewItem(ctx context.Context, item ReviewItem) error {
	_, err := s.DB.ExecContext(ctx, s.q(`INSERT INTO review_items (id, campaign_id, user_id, role_id, reviewer_id, decision, decided_at) VALUES (?, ?, ?, ?, ?, ?, ?)`),
		item.ID, item.CampaignID, item.UserID, item.RoleID, item.ReviewerID, item.Decision, item.DecidedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("add review item: %w", ErrConflict)
		}
		return err
	}
	return nil
}

func (s *Store) ListReviewItems(ctx context.Context, campaignID string) ([]ReviewItem, error) {
	rows, err := s.DB.QueryContext(ctx, s.q(`SELECT id, campaign_id, user_id, role_id, reviewer_id, decision, decided_at FROM review_items WHERE campaign_id = ? ORDER BY id`), campaignID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ReviewItem{}
	for rows.Next() {
		var it ReviewItem
		if err := rows.Scan(&it.ID, &it.CampaignID, &it.UserID, &it.RoleID, &it.ReviewerID, &it.Decision, &it.DecidedAt); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) DecideReviewItem(ctx context.Context, campaignID, itemID, reviewerID, decision string, now int64) error {
	if decision != "certified" && decision != "revoked" {
		return fmt.Errorf("invalid decision %q: must be certified or revoked", decision)
	}
	var cur string
	err := s.DB.QueryRowContext(ctx, s.q(`SELECT decision FROM review_items WHERE id = ? AND campaign_id = ?`), itemID, campaignID).Scan(&cur)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("decide review item: %w", ErrNotFound)
		}
		return err
	}
	if cur != "pending" {
		return fmt.Errorf("decide review item %q: already decided (%q)", itemID, cur)
	}
	res, err := s.DB.ExecContext(ctx, s.q(`UPDATE review_items SET decision = ?, reviewer_id = ?, decided_at = ? WHERE id = ? AND campaign_id = ? AND decision = ?`),
		decision, reviewerID, now, itemID, campaignID, "pending")
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("decide review item %q: already decided", itemID)
	}
	return nil
}

func (s *Store) CloseCampaign(ctx context.Context, orgID, campaignID string, now int64) error {
	var id string
	err := s.DB.QueryRowContext(ctx, s.q(`SELECT id FROM review_campaigns WHERE id = ? AND org_id = ?`), campaignID, orgID).Scan(&id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("close campaign: %w", ErrNotFound)
		}
		return err
	}
	var pending int
	if err := s.DB.QueryRowContext(ctx, s.q(`SELECT COUNT(*) FROM review_items WHERE campaign_id = ? AND decision = ?`), campaignID, "pending").Scan(&pending); err != nil {
		return err
	}
	if pending > 0 {
		return fmt.Errorf("close campaign %q: %d pending items remain", campaignID, pending)
	}
	if _, err := s.DB.ExecContext(ctx, s.q(`UPDATE review_campaigns SET status = ?, closed_at = ? WHERE id = ?`), "closed", now, campaignID); err != nil {
		return err
	}
	return nil
}

func (s *Store) IdemGet(ctx context.Context, orgID, key string) (method, path, reqHash string, respStatus int, respBody string, err error) {
	err = s.DB.QueryRowContext(ctx, s.q(`SELECT method, path, req_hash, resp_status, resp_body FROM idem WHERE org_id = ? AND key = ?`), orgID, key).Scan(
		&method, &path, &reqHash, &respStatus, &respBody)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", "", 0, "", fmt.Errorf("idem get: %w", ErrNotFound)
		}
		return "", "", "", 0, "", err
	}
	return method, path, reqHash, respStatus, respBody, nil
}

func (s *Store) IdemPut(ctx context.Context, orgID, key, method, path, reqHash string, respStatus int, respBody string, now int64) error {
	_, err := s.DB.ExecContext(ctx, s.q(`INSERT INTO idem (org_id, key, method, path, req_hash, resp_status, resp_body, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(org_id, key) DO UPDATE SET method = excluded.method, path = excluded.path, req_hash = excluded.req_hash, resp_status = excluded.resp_status, resp_body = excluded.resp_body, created_at = excluded.created_at`),
		orgID, key, method, path, reqHash, respStatus, respBody, now)
	return err
}
