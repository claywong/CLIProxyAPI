package executor

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

// defaultMimicryFingerprintTTL governs the in-memory fingerprint cache when
// the operator has not customised claude-oauth-mimicry.fingerprint-cache-ttl.
const defaultMimicryFingerprintTTL = 7 * 24 * time.Hour

var (
	oauthMimicryStoreOnce sync.Once
	oauthMimicryStore     helps.FingerprintStore
	oauthMimicryStoreTTL  time.Duration
)

// claudeOAuthMimicryEnabled reports whether the OAuth mimicry pipeline should
// run for the current request. The setting defaults to true so existing
// deployments pick up the safer fingerprint without explicit opt-in.
func claudeOAuthMimicryEnabled(cfg *config.Config) bool {
	if cfg == nil || cfg.ClaudeOAuthMimicry.Enabled == nil {
		return true
	}
	return *cfg.ClaudeOAuthMimicry.Enabled
}

// claudeOAuthMimicryTTL parses fingerprint-cache-ttl, falling back to
// defaultMimicryFingerprintTTL when unset or malformed.
func claudeOAuthMimicryTTL(cfg *config.Config) time.Duration {
	if cfg == nil {
		return defaultMimicryFingerprintTTL
	}
	raw := cfg.ClaudeOAuthMimicry.FingerprintCacheTTL
	if raw == "" {
		return defaultMimicryFingerprintTTL
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		log.Warnf("claude-oauth-mimicry.fingerprint-cache-ttl %q invalid, using default %s", raw, defaultMimicryFingerprintTTL)
		return defaultMimicryFingerprintTTL
	}
	return d
}

// getClaudeOAuthMimicryStore returns the process-wide in-memory fingerprint
// store. The TTL is captured on first use; subsequent calls reuse the same
// store regardless of later config changes to keep cached entries stable.
func getClaudeOAuthMimicryStore(cfg *config.Config) helps.FingerprintStore {
	oauthMimicryStoreOnce.Do(func() {
		oauthMimicryStoreTTL = claudeOAuthMimicryTTL(cfg)
		oauthMimicryStore = helps.NewMemoryFingerprintStore(oauthMimicryStoreTTL)
	})
	return oauthMimicryStore
}

// loadClaudeOAuthFingerprint fetches or creates the per-account fingerprint
// for the given auth record. Cache errors are downgraded to warnings; the
// caller never blocks on cache I/O.
func loadClaudeOAuthFingerprint(ctx context.Context, cfg *config.Config, auth *cliproxyauth.Auth) (*helps.OAuthFingerprint, error) {
	store := getClaudeOAuthMimicryStore(cfg)
	return helps.GetOrCreateOAuthFingerprint(ctx, store, auth, func(err error) {
		log.Warnf("claude oauth fingerprint cache error: %v", err)
	})
}

// rewriteClaudeOAuthBody applies the mimicry body transforms to a Claude OAuth
// payload. Currently this rewrites metadata.user_id; future body-level edits
// (cc_version sync, beta-conditional sanitisation) belong here as well.
// Returns the body unchanged when mimicry is disabled, when the auth is not
// OAuth, or when the fingerprint lookup fails.
func rewriteClaudeOAuthBody(
	ctx context.Context,
	cfg *config.Config,
	auth *cliproxyauth.Auth,
	apiKey string,
	body []byte,
) ([]byte, *helps.OAuthFingerprint) {
	if !claudeOAuthMimicryEnabled(cfg) || !isClaudeOAuthToken(apiKey) || auth == nil {
		return body, nil
	}
	fp, err := loadClaudeOAuthFingerprint(ctx, cfg, auth)
	if err != nil || fp == nil {
		return body, nil
	}
	uaVersion := helps.ExtractCLIVersion(fp.UserAgent)
	rewritten := helps.RewriteOAuthUserID(body, fp.AccountID, fp.AccountUUID, fp.DeviceID, uaVersion)
	return rewritten, fp
}

// stampClaudeOAuthHeaders overrides every identity header on req with the
// fingerprint template values and syncs X-Claude-Code-Session-Id with the
// session id embedded in body. No-op when fp is nil.
func stampClaudeOAuthHeaders(req *http.Request, fp *helps.OAuthFingerprint, body []byte, isStream bool) {
	if fp == nil {
		return
	}
	helps.ApplyOAuthMimicryHeaders(req, fp, isStream)
	helps.SyncOAuthSessionHeader(req, body)
}
