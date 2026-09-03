package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/unveiledhistory49/gatekeeper/internal/api"
	"github.com/unveiledhistory49/gatekeeper/internal/auth"
	"github.com/unveiledhistory49/gatekeeper/internal/config"
	"github.com/unveiledhistory49/gatekeeper/internal/db"
	"github.com/unveiledhistory49/gatekeeper/internal/store"
)

func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func printJSON(v any) {
	b, _ := json.Marshal(v)
	fmt.Println(string(b))
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error: "+err.Error())
	os.Exit(1)
}

func openStore(url string) (*store.Store, error) {
	pool, driver, err := db.Open(url)
	if err != nil {
		return nil, err
	}
	if err := db.Migrate(pool); err != nil {
		return nil, err
	}
	return store.New(pool, driver), nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: gatekeeper <provision-org|create-user|serve|migrate|verify-audit> [flags]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "provision-org":
		cmdProvisionOrg(os.Args[2:])
	case "create-user":
		cmdCreateUser(os.Args[2:])
	case "serve":
		cmdServe(os.Args[2:])
	case "migrate":
		cmdMigrate(os.Args[2:])
	case "verify-audit":
		cmdVerifyAudit(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "unknown subcommand: "+os.Args[1])
		os.Exit(2)
	}
}

func cmdProvisionOrg(args []string) {
	fs := flag.NewFlagSet("provision-org", flag.ExitOnError)
	name := fs.String("name", "", "org name")
	email := fs.String("email", "", "admin email")
	password := fs.String("password", "", "admin password (min 12 chars)")
	dbURL := fs.String("db", "", "database URL (overrides GATEKEEPER_DATABASE_URL)")
	_ = fs.Parse(args)
	if *name == "" || *email == "" || *password == "" {
		fmt.Fprintln(os.Stderr, "provision-org requires --name --email --password")
		os.Exit(2)
	}
	cfg := config.Load()
	if *dbURL != "" {
		cfg.DatabaseURL = *dbURL
	}
	ctx := context.Background()
	now := time.Now().Unix()
	st, err := openStore(cfg.DatabaseURL)
	if err != nil {
		fail(err)
	}
	orgID := newID()
	if err := st.CreateOrg(ctx, orgID, *name, now); err != nil {
		fail(err)
	}
	roleID := newID()
	if err := st.CreateRole(ctx, store.Role{ID: roleID, OrgID: orgID, Name: "admin", Description: "Administrator", CreatedAt: now}); err != nil {
		fail(err)
	}
	if err := st.SetRolePermissions(ctx, roleID, []string{"*"}); err != nil {
		fail(err)
	}
	ph, err := auth.HashPassword(*password)
	if err != nil {
		fail(err)
	}
	userID := newID()
	userName := strings.Split(*email, "@")[0]
	if err := st.CreateUser(ctx, store.User{
		ID: userID, OrgID: orgID, Email: *email, Name: userName,
		PasswordHash: ph, Status: "active", CreatedAt: now,
	}); err != nil {
		fail(err)
	}
	if err := st.SetUserRoles(ctx, orgID, userID, []string{roleID}); err != nil {
		fail(err)
	}
	rawKey, hash, prefix := auth.NewAPIKey(cfg.Pepper)
	if err := st.CreateAPIKey(ctx, store.APIKey{
		ID: newID(), OrgID: orgID, Name: "provision", KeyHash: hash,
		Prefix: prefix, ExpiresAt: 0, Revoked: false, CreatedAt: now,
	}); err != nil {
		fail(err)
	}
	_, _ = st.AppendAudit(ctx, orgID, userID, "orgs.provision", orgID, *name, now)
	printJSON(map[string]string{"org_id": orgID, "user_id": userID, "api_key": rawKey})
}

func cmdCreateUser(args []string) {
	fs := flag.NewFlagSet("create-user", flag.ExitOnError)
	orgID := fs.String("org", "", "org id")
	email := fs.String("email", "", "email")
	name := fs.String("name", "", "display name")
	password := fs.String("password", "", "password (min 12 chars)")
	roles := fs.String("roles", "", "comma-separated role names or ids")
	dbURL := fs.String("db", "", "database URL (overrides GATEKEEPER_DATABASE_URL)")
	_ = fs.Parse(args)
	if *orgID == "" || *email == "" || *password == "" {
		fmt.Fprintln(os.Stderr, "create-user requires --org --email --password")
		os.Exit(2)
	}
	cfg := config.Load()
	if *dbURL != "" {
		cfg.DatabaseURL = *dbURL
	}
	ctx := context.Background()
	now := time.Now().Unix()
	st, err := openStore(cfg.DatabaseURL)
	if err != nil {
		fail(err)
	}
	display := *name
	if display == "" {
		display = strings.Split(*email, "@")[0]
	}
	ph, err := auth.HashPassword(*password)
	if err != nil {
		fail(err)
	}
	userID := newID()
	if err := st.CreateUser(ctx, store.User{
		ID: userID, OrgID: *orgID, Email: *email, Name: display,
		PasswordHash: ph, Status: "active", CreatedAt: now,
	}); err != nil {
		fail(err)
	}
	if *roles != "" {
		all, err := st.ListRoles(ctx, *orgID)
		if err != nil {
			fail(err)
		}
		byName := map[string]string{}
		byID := map[string]string{}
		for _, r := range all {
			byName[r.Name] = r.ID
			byID[r.ID] = r.ID
		}
		var ids []string
		for _, want := range strings.Split(*roles, ",") {
			want = strings.TrimSpace(want)
			if want == "" {
				continue
			}
			if id, ok := byID[want]; ok {
				ids = append(ids, id)
			} else if id, ok := byName[want]; ok {
				ids = append(ids, id)
			} else {
				fail(fmt.Errorf("role not found: %s", want))
			}
		}
		if err := st.SetUserRoles(ctx, *orgID, userID, ids); err != nil {
			fail(err)
		}
	}
	_, _ = st.AppendAudit(ctx, *orgID, userID, "users.create", userID, *email, now)
	printJSON(map[string]string{"org_id": *orgID, "user_id": userID, "email": *email})
}

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	dbURL := fs.String("db", "", "database URL (overrides GATEKEEPER_DATABASE_URL)")
	addr := fs.String("addr", "", "listen addr (overrides GATEKEEPER_ADDR)")
	_ = fs.Parse(args)
	cfg := config.Load()
	if *dbURL != "" {
		cfg.DatabaseURL = *dbURL
	}
	if *addr != "" {
		cfg.Addr = *addr
	}
	ctx := context.Background()
	st, err := openStore(cfg.DatabaseURL)
	if err != nil {
		fail(err)
	}
	deps := api.Deps{Store: st, Auth: &auth.Authenticator{Store: st, Pepper: cfg.Pepper}, Cfg: cfg}
	if cfg.OIDCEnabled() {
		if v, err := auth.NewOIDCVerifier(ctx, cfg.OIDCIssuer, cfg.OIDCClientID); err == nil {
			deps.OIDC = v
		} else {
			fmt.Fprintln(os.Stderr, "warning: oidc verifier: "+err.Error())
		}
		base := strings.TrimSuffix(cfg.OIDCIssuer, "/")
		deps.OAuth = auth.NewOAuthClient(cfg.OIDCClientID, cfg.OIDCClientSecret, cfg.OIDCRedirectURL,
			base+"/authorize", base+"/token", []string{"openid", "email", "profile"})
	}
	srv := &http.Server{Addr: cfg.Addr, Handler: api.NewRouter(deps)}
	fmt.Fprintln(os.Stderr, "gatekeeper listening on "+cfg.Addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fail(err)
	}
}

func cmdMigrate(args []string) {
	fs := flag.NewFlagSet("migrate", flag.ExitOnError)
	dbURL := fs.String("db", "", "database URL (overrides GATEKEEPER_DATABASE_URL)")
	_ = fs.Parse(args)
	cfg := config.Load()
	if *dbURL != "" {
		cfg.DatabaseURL = *dbURL
	}
	pool, _, err := db.Open(cfg.DatabaseURL)
	if err != nil {
		fail(err)
	}
	defer pool.Close()
	if err := db.Migrate(pool); err != nil {
		fail(err)
	}
	printJSON(map[string]bool{"ok": true})
}

func cmdVerifyAudit(args []string) {
	fs := flag.NewFlagSet("verify-audit", flag.ExitOnError)
	orgID := fs.String("org", "", "org id")
	dbURL := fs.String("db", "", "database URL (overrides GATEKEEPER_DATABASE_URL)")
	_ = fs.Parse(args)
	if *orgID == "" {
		fmt.Fprintln(os.Stderr, "verify-audit requires --org")
		os.Exit(2)
	}
	cfg := config.Load()
	if *dbURL != "" {
		cfg.DatabaseURL = *dbURL
	}
	ctx := context.Background()
	pool, driver, err := db.Open(cfg.DatabaseURL)
	if err != nil {
		fail(err)
	}
	defer pool.Close()
	st := store.New(pool, driver)
	if err := st.VerifyAuditChain(ctx, *orgID); err != nil {
		b, _ := json.Marshal(map[string]any{"ok": false, "error": err.Error()})
		fmt.Fprintln(os.Stderr, string(b))
		os.Exit(1)
	}
	printJSON(map[string]bool{"ok": true})
}
