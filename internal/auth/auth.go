// Package auth provides password hashing (argon2id), API-key and session
// token issuance, OIDC verification, and HTTP identity middleware for
// Gatekeeper.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/unveiledhistory49/gatekeeper/internal/store"
	"golang.org/x/crypto/argon2"
	"golang.org/x/oauth2"
)

// Argon2id parameters for password hashing.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // 64 MiB in KiB
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16
	minPassLen   = 12
)

// SessionCookie is the cookie carrying the raw session token.
const SessionCookie = "gk_session"

// APIKeyHeader is the header carrying the raw API key.
const APIKeyHeader = "X-API-Key"

// Identity kinds.
const (
	KindSession = "session"
	KindAPIKey  = "api_key"
)

// HashPassword hashes pw with argon2id (time=3, memory=64MB, threads=4,
// keylen=32, 16-byte random salt) and encodes it as
// $argon2id$v=19$m=65536,t=3,p=4$<b64salt>$<b64hash> (unpadded base64).
// Passwords shorter than 12 characters are rejected.
func HashPassword(pw string) (string, error) {
	if len(pw) < minPassLen {
		return "", fmt.Errorf("auth: password must be at least %d characters", minPassLen)
	}
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: salt: %w", err)
	}
	hash := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		enc.EncodeToString(salt), enc.EncodeToString(hash)), nil
}

// CheckPassword verifies pw against an encoded hash produced by HashPassword.
// It returns false for malformed encodings and uses constant-time comparison.
func CheckPassword(encoded, pw string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	var memory uint32
	var time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return false
	}
	if memory == 0 || time == 0 || threads == 0 {
		return false
	}
	enc := base64.RawStdEncoding
	salt, err := enc.DecodeString(parts[4])
	if err != nil || len(salt) != argonSaltLen {
		return false
	}
	want, err := enc.DecodeString(parts[5])
	if err != nil || len(want) != argonKeyLen {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, time, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// sha256Hex returns the lowercase hex of sha256(s).
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// NewAPIKey mints a raw API key of the form gk_live_<32 hex chars> (16 random
// bytes) and derives its storage hash as sha256hex(pepper+"::"+raw). prefix is
// the last 8 characters of raw for display/lookup purposes.
func NewAPIKey(pepper string) (raw, hash, prefix string) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Sprintf("auth: api key randomness: %v", err))
	}
	raw = "gk_live_" + hex.EncodeToString(buf)
	return raw, HashAPIKey(pepper, raw), raw[len(raw)-8:]
}

// HashAPIKey derives the storage hash for a raw API key.
func HashAPIKey(pepper, raw string) string {
	return sha256Hex(pepper + "::" + raw)
}

// NewSessionToken mints a raw session token (32 random bytes, hex-encoded)
// and its storage hash sha256hex(raw).
func NewSessionToken() (raw, hash string) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Sprintf("auth: session token randomness: %v", err))
	}
	raw = hex.EncodeToString(buf)
	return raw, HashSessionToken(raw)
}

// HashSessionToken derives the storage hash for a raw session token.
func HashSessionToken(raw string) string {
	return sha256Hex(raw)
}

// Claims is the normalized identity extracted from a verified ID token.
type Claims struct {
	Subject string
	Email   string
	Name    string
}

// Verifier verifies a raw ID token and returns normalized claims.
type Verifier interface {
	Verify(ctx context.Context, rawToken string) (Claims, error)
}

// oidcVerifier adapts go-oidc verification to the Verifier interface.
type oidcVerifier struct {
	verifier *oidc.IDTokenVerifier
}

// NewOIDCVerifier builds a live go-oidc verifier for issuer that accepts
// tokens minted for clientID.
func NewOIDCVerifier(ctx context.Context, issuer, clientID string) (Verifier, error) {
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("auth: oidc provider: %w", err)
	}
	return &oidcVerifier{verifier: provider.Verifier(&oidc.Config{ClientID: clientID})}, nil
}

// Verify checks the token signature/issuer/expiry/audience and extracts claims.
func (v *oidcVerifier) Verify(ctx context.Context, rawToken string) (Claims, error) {
	tok, err := v.verifier.Verify(ctx, rawToken)
	if err != nil {
		return Claims{}, fmt.Errorf("auth: verify id token: %w", err)
	}
	var extra struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := tok.Claims(&extra); err != nil {
		return Claims{}, fmt.Errorf("auth: id token claims: %w", err)
	}
	return Claims{Subject: tok.Subject, Email: extra.Email, Name: extra.Name}, nil
}

// OAuthClient wraps an OAuth2 authorization-code flow configuration.
type OAuthClient struct {
	Cfg      *oauth2.Config
	AuthURL  string
	TokenURL string
}

// NewOAuthClient builds an OAuth2 client for the authorization-code flow.
func NewOAuthClient(clientID, secret, redirect, authURL, tokenURL string, scopes []string) *OAuthClient {
	return &OAuthClient{
		Cfg: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: secret,
			RedirectURL:  redirect,
			Scopes:       scopes,
			Endpoint:     oauth2.Endpoint{AuthURL: authURL, TokenURL: tokenURL},
		},
		AuthURL:  authURL,
		TokenURL: tokenURL,
	}
}

// AuthCodeURL returns the URL to redirect the user to for login.
func (c *OAuthClient) AuthCodeURL(state string) string {
	return c.Cfg.AuthCodeURL(state)
}

// Exchange swaps an authorization code for tokens and returns the raw
// id_token from the token response.
func (c *OAuthClient) Exchange(ctx context.Context, code string) (string, error) {
	tok, err := c.Cfg.Exchange(ctx, code)
	if err != nil {
		return "", fmt.Errorf("auth: code exchange: %w", err)
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return "", errors.New("auth: token response missing id_token")
	}
	return raw, nil
}

// Identity is the resolved caller attached to a request context. Kind is
// "session" for user sessions or "api_key" for org-scoped service keys (which
// carry no UserID).
type Identity struct {
	OrgID  string
	UserID string
	Kind   string
}

// ctxKey is the unexported context key for Identity.
type ctxKey struct{}

// IdentityFrom returns the Identity attached to ctx, if any.
func IdentityFrom(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(ctxKey{}).(Identity)
	return id, ok
}

// ContextWithIdentity attaches id to ctx. It is exported so other packages
// (handlers, tests) can seed identities without going through the middleware.
func ContextWithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// Authenticator resolves request credentials into an Identity using Store.
type Authenticator struct {
	Store  *store.Store
	Pepper string
}

// AuthenticateAPIKey resolves a raw API key to its stored record, enforcing
// revocation and expiry. It exists for middleware/CLI/test reuse; the hash
// lookup itself is the comparison (no plaintext to compare in constant time).
// The spec'd signature carries no context, so store calls use
// context.Background; use authenticateAPIKey with an explicit ctx when one is
// available (as Middleware does).
func (a *Authenticator) AuthenticateAPIKey(raw string) (store.APIKey, error) {
	return a.authenticateAPIKey(context.Background(), raw)
}

// authenticateAPIKey is the context-aware core of AuthenticateAPIKey.
func (a *Authenticator) authenticateAPIKey(ctx context.Context, raw string) (store.APIKey, error) {
	key, err := a.Store.GetAPIKeyByHash(ctx, HashAPIKey(a.Pepper, raw))
	if err != nil {
		return store.APIKey{}, fmt.Errorf("auth: unknown api key")
	}
	if key.Revoked {
		return store.APIKey{}, fmt.Errorf("auth: api key revoked")
	}
	if key.ExpiresAt != 0 && time.Now().Unix() >= key.ExpiresAt {
		return store.APIKey{}, fmt.Errorf("auth: api key expired")
	}
	return key, nil
}

// authenticateSession resolves a raw session token to an Identity, enforcing
// expiry and requiring the bound user to exist and be active (non-active,
// including suspended, is rejected). The user is loaded org-scoped from the
// session so sessions cannot wander across orgs.
func (a *Authenticator) authenticateSession(ctx context.Context, raw string) (Identity, bool) {
	sess, err := a.Store.GetSessionByHash(ctx, HashSessionToken(raw))
	if err != nil {
		return Identity{}, false
	}
	if sess.ExpiresAt != 0 && time.Now().Unix() >= sess.ExpiresAt {
		return Identity{}, false
	}
	user, err := a.Store.GetUser(ctx, sess.OrgID, sess.UserID)
	if err != nil {
		return Identity{}, false
	}
	if user.Status != "active" {
		return Identity{}, false
	}
	orgID := user.OrgID
	if orgID == "" {
		orgID = sess.OrgID
	}
	return Identity{OrgID: orgID, UserID: user.ID, Kind: KindSession}, true
}

// RandomState returns a random URL-safe state string for OAuth login flows.
func RandomState() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("auth: state randomness: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// writeUnauthorized renders a 401 JSON error.
func writeUnauthorized(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// Middleware resolves credentials in order: (1) the gk_session cookie as a
// user session (hash lookup, expiry check, user load, suspended rejection);
// (2) the X-API-Key header as an org-scoped service identity (UserID == "").
// Either success attaches an Identity to the request context; otherwise it
// responds 401 with a JSON {"error":...} body.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if cookie, err := r.Cookie(SessionCookie); err == nil && cookie.Value != "" {
			if id, ok := a.authenticateSession(ctx, cookie.Value); ok {
				next.ServeHTTP(w, r.WithContext(ContextWithIdentity(r.Context(), id)))
				return
			}
		}
		if raw := r.Header.Get(APIKeyHeader); raw != "" {
			if key, err := a.authenticateAPIKey(ctx, raw); err == nil {
				id := Identity{OrgID: key.OrgID, UserID: "", Kind: KindAPIKey}
				next.ServeHTTP(w, r.WithContext(ContextWithIdentity(r.Context(), id)))
				return
			}
		}
		writeUnauthorized(w, "authentication required")
	})
}
