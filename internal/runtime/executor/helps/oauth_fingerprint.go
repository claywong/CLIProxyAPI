package helps

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

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
		fp.DeviceID = GenerateDeviceID()
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
	fp.DeviceID = GenerateDeviceID()
	fp.CreatedAt = time.Now()
	fp.UpdatedAt = fp.CreatedAt
	if store != nil {
		if err := store.Set(ctx, accountID, &fp); err != nil && onCacheError != nil {
			onCacheError(err)
		}
	}
	return &fp, nil
}
