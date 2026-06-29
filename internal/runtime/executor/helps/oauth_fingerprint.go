package helps

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

// deviceIDFileSuffix is appended to the sanitized account ID to form each
// account's device_id file name (e.g. "claude-foo@bar.com.device_id").
const deviceIDFileSuffix = ".device_id"

var (
	deviceIDMu    sync.Mutex
	deviceIDDir   string                // persistence directory; empty means fallback-only
	deviceIDCache = map[string]string{} // per-account resolved device_id cache
)

// ConfigureDeviceIDDir sets the directory used to persist per-account device_id
// files. A new directory clears the resolution cache so values are re-read.
// Safe for concurrent use.
func ConfigureDeviceIDDir(dir string) {
	deviceIDMu.Lock()
	defer deviceIDMu.Unlock()
	if dir == "" || dir == deviceIDDir {
		return
	}
	deviceIDDir = dir
	deviceIDCache = map[string]string{}
}

// deviceIDFileName maps an account ID to a flat, filesystem-safe file name. The
// account ID is the auth record's relative path (e.g. "claude-foo@bar.com.json");
// the trailing ".json" is dropped and path separators / other unsafe characters
// are replaced with underscores so each account maps to a single flat file.
func deviceIDFileName(accountID string) string {
	base := strings.TrimSuffix(accountID, ".json")
	safe := strings.Map(func(r rune) rune {
		switch r {
		case '/', '\\', ':':
			return '_'
		default:
			return r
		}
	}, base)
	return safe + deviceIDFileSuffix
}

// resolveDeviceID returns the persistent device_id for a single account. Each
// account maps to its own file under the configured directory. The result is
// read once and cached. Existing accounts were seeded with a fixed device_id
// out-of-band; any account without a file here is treated as new and gets a
// freshly generated random device_id, which is then persisted with no
// expiration. When no directory is configured, or accountID is empty, a random
// device_id is returned without touching disk.
func resolveDeviceID(accountID string) string {
	deviceIDMu.Lock()
	defer deviceIDMu.Unlock()
	if v, ok := deviceIDCache[accountID]; ok {
		return v
	}
	if deviceIDDir == "" || accountID == "" {
		val := GenerateDeviceID()
		deviceIDCache[accountID] = val
		return val
	}
	path := filepath.Join(deviceIDDir, deviceIDFileName(accountID))
	if data, err := os.ReadFile(path); err == nil {
		if v := strings.TrimSpace(string(data)); v != "" {
			deviceIDCache[accountID] = v
			return v
		}
	}
	// No file for this account: treat it as new, generate a random device_id
	// and persist it for next time.
	val := GenerateDeviceID()
	if err := os.MkdirAll(deviceIDDir, 0o755); err != nil {
		log.Warnf("claude oauth mimicry: create device_id dir failed: %v", err)
	} else if err := os.WriteFile(path, []byte(val), 0o600); err != nil {
		log.Warnf("claude oauth mimicry: persist device_id failed: %v", err)
	}
	deviceIDCache[accountID] = val
	return val
}

// OAuthFingerprint holds the per-account Claude Code CLI identity used by the
// OAuth mimicry pipeline. AccountID and AccountUUID are sourced from the auth
// record; the remaining fields seed the wire headers and metadata.user_id.
type OAuthFingerprint struct {
	AccountID               string
	AccountUUID             string
	DeviceID                string
	UserAgent               string
	StainlessArch           string
	StainlessLang           string
	StainlessOS             string
	StainlessPackageVersion string
	StainlessRuntime        string
	StainlessRuntimeVersion string
	StainlessRetryCount     string
	StainlessTimeout        string
	CreatedAt               time.Time
	UpdatedAt               time.Time
}

// Clone returns a deep copy of the fingerprint suitable for safe per-request use.
func (fp OAuthFingerprint) Clone() OAuthFingerprint {
	return fp
}

// FingerprintStore is the persistence contract for OAuthFingerprint records.
// Implementations must be safe for concurrent use.
type FingerprintStore interface {
	Get(ctx context.Context, accountID string) (*OAuthFingerprint, bool, error)
	Set(ctx context.Context, accountID string, fp *OAuthFingerprint) error
}

// memoryFingerprintStore is the default in-memory implementation. Records expire
// after ttl; each successful Get refreshes the entry's deadline.
type memoryFingerprintStore struct {
	mu      sync.Mutex
	entries map[string]*memoryFingerprintEntry
	ttl     time.Duration
}

type memoryFingerprintEntry struct {
	fp       *OAuthFingerprint
	expireAt time.Time
}

// NewMemoryFingerprintStore creates an in-memory FingerprintStore. ttl controls
// per-entry expiration; pass <=0 to disable expiration.
func NewMemoryFingerprintStore(ttl time.Duration) FingerprintStore {
	return &memoryFingerprintStore{
		entries: make(map[string]*memoryFingerprintEntry),
		ttl:     ttl,
	}
}

func (s *memoryFingerprintStore) Get(_ context.Context, accountID string) (*OAuthFingerprint, bool, error) {
	if accountID == "" {
		return nil, false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[accountID]
	if !ok {
		return nil, false, nil
	}
	if s.ttl > 0 && time.Now().After(entry.expireAt) {
		delete(s.entries, accountID)
		return nil, false, nil
	}
	if s.ttl > 0 {
		entry.expireAt = time.Now().Add(s.ttl)
	}
	cloned := entry.fp.Clone()
	return &cloned, true, nil
}

func (s *memoryFingerprintStore) Set(_ context.Context, accountID string, fp *OAuthFingerprint) error {
	if accountID == "" || fp == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cloned := fp.Clone()
	entry := &memoryFingerprintEntry{fp: &cloned}
	if s.ttl > 0 {
		entry.expireAt = time.Now().Add(s.ttl)
	}
	s.entries[accountID] = entry
	return nil
}

// GenerateDeviceID returns a 64-char lowercase hex string suitable for the
// metadata.user_id.device_id field. Backed by crypto/rand.
func GenerateDeviceID() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand.Read should not fail in practice; fall back to time-based
		// entropy via the existing fake-user-id generator (returns 64 hex bytes
		// inside its userID format).
		return GenerateFakeUserID()[5:69]
	}
	return hex.EncodeToString(buf)
}

// extractAccountUUID reads auth.Metadata["account_uuid"] in a type-safe way.
// Missing or non-string entries yield "".
func extractAccountUUID(auth *cliproxyauth.Auth) string {
	if auth == nil || auth.Metadata == nil {
		return ""
	}
	if v, ok := auth.Metadata["account_uuid"].(string); ok {
		return v
	}
	return ""
}

// GetOrCreateOAuthFingerprint returns the cached fingerprint for the given auth
// record or seeds a fresh one from FingerprintTemplate when absent. The store
// receives the new entry; cache errors are swallowed by the caller-supplied
// onCacheError hook (nil → silent).
func GetOrCreateOAuthFingerprint(
	ctx context.Context,
	store FingerprintStore,
	auth *cliproxyauth.Auth,
	onCacheError func(error),
) (*OAuthFingerprint, error) {
	if auth == nil {
		return nil, nil
	}
	accountID := auth.ID
	if accountID == "" {
		// Without a stable accountID we cannot key the cache; return an
		// ephemeral fingerprint built from the template.
		fp := FingerprintTemplate
		fp.AccountID = ""
		fp.AccountUUID = extractAccountUUID(auth)
		fp.DeviceID = resolveDeviceID(accountID)
		fp.CreatedAt = time.Now()
		fp.UpdatedAt = fp.CreatedAt
		return &fp, nil
	}
	accountUUID := extractAccountUUID(auth)

	if store != nil {
		if fp, ok, err := store.Get(ctx, accountID); err == nil && ok {
			// Backfill account_uuid if the auth record gained it after the
			// fingerprint was first cached.
			if fp.AccountUUID == "" && accountUUID != "" {
				fp.AccountUUID = accountUUID
				fp.UpdatedAt = time.Now()
				if errSet := store.Set(ctx, accountID, fp); errSet != nil && onCacheError != nil {
					onCacheError(errSet)
				}
			}
			return fp, nil
		} else if err != nil && onCacheError != nil {
			onCacheError(err)
		}
	}

	fp := FingerprintTemplate
	fp.AccountID = accountID
	fp.AccountUUID = accountUUID
	fp.DeviceID = resolveDeviceID(accountID)
	fp.CreatedAt = time.Now()
	fp.UpdatedAt = fp.CreatedAt
	if store != nil {
		if err := store.Set(ctx, accountID, &fp); err != nil && onCacheError != nil {
			onCacheError(err)
		}
	}
	return &fp, nil
}
