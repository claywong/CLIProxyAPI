package helps

import (
	"context"
	"errors"
	"testing"
	"time"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestGenerateDeviceID_Format(t *testing.T) {
	id := GenerateDeviceID()
	if len(id) != 64 {
		t.Fatalf("expected 64-char id, got %d (%s)", len(id), id)
	}
	for _, r := range id {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			t.Fatalf("expected lowercase hex, got %q", r)
		}
	}
}

func TestMemoryFingerprintStore_RoundTrip(t *testing.T) {
	store := NewMemoryFingerprintStore(time.Hour)
	fp := &OAuthFingerprint{AccountID: "acct-1", DeviceID: "dev"}
	if err := store.Set(context.Background(), "acct-1", fp); err != nil {
		t.Fatal(err)
	}
	got, ok, err := store.Get(context.Background(), "acct-1")
	if err != nil || !ok {
		t.Fatalf("Get failed: ok=%v err=%v", ok, err)
	}
	if got.DeviceID != "dev" {
		t.Errorf("DeviceID mismatch: %s", got.DeviceID)
	}
}

func TestMemoryFingerprintStore_ExpiresEntries(t *testing.T) {
	store := NewMemoryFingerprintStore(10 * time.Millisecond)
	_ = store.Set(context.Background(), "acct-1", &OAuthFingerprint{AccountID: "acct-1"})
	time.Sleep(30 * time.Millisecond)
	if _, ok, _ := store.Get(context.Background(), "acct-1"); ok {
		t.Errorf("entry should have expired")
	}
}

func TestMemoryFingerprintStore_EmptyKey(t *testing.T) {
	store := NewMemoryFingerprintStore(0)
	if _, ok, _ := store.Get(context.Background(), ""); ok {
		t.Errorf("empty key should miss")
	}
	if err := store.Set(context.Background(), "", &OAuthFingerprint{}); err != nil {
		t.Errorf("Set with empty key should be no-op, got %v", err)
	}
}

func TestGetOrCreateOAuthFingerprint_SeedsFromTemplate(t *testing.T) {
	store := NewMemoryFingerprintStore(time.Hour)
	auth := &cliproxyauth.Auth{ID: "acct-1", Metadata: map[string]any{"account_uuid": "uuid-1"}}
	fp, err := GetOrCreateOAuthFingerprint(context.Background(), store, auth, nil)
	if err != nil {
		t.Fatal(err)
	}
	if fp.AccountID != "acct-1" || fp.AccountUUID != "uuid-1" {
		t.Errorf("identity mismatch: %+v", fp)
	}
	if fp.UserAgent != TemplateUserAgent {
		t.Errorf("UA not seeded from template: %s", fp.UserAgent)
	}
	if fp.DeviceID == "" {
		t.Error("DeviceID empty")
	}

	// Second call should hit cache and reuse DeviceID.
	fp2, _ := GetOrCreateOAuthFingerprint(context.Background(), store, auth, nil)
	if fp2.DeviceID != fp.DeviceID {
		t.Errorf("DeviceID changed across calls: %s vs %s", fp.DeviceID, fp2.DeviceID)
	}
}

func TestGetOrCreateOAuthFingerprint_BackfillsAccountUUID(t *testing.T) {
	store := NewMemoryFingerprintStore(time.Hour)
	// First call: account_uuid missing in auth.
	authMissing := &cliproxyauth.Auth{ID: "acct-x"}
	fp1, _ := GetOrCreateOAuthFingerprint(context.Background(), store, authMissing, nil)
	if fp1.AccountUUID != "" {
		t.Fatalf("expected empty AccountUUID, got %s", fp1.AccountUUID)
	}
	// Second call: account_uuid now present; expect backfill.
	authNow := &cliproxyauth.Auth{ID: "acct-x", Metadata: map[string]any{"account_uuid": "late-uuid"}}
	fp2, _ := GetOrCreateOAuthFingerprint(context.Background(), store, authNow, nil)
	if fp2.AccountUUID != "late-uuid" {
		t.Errorf("expected backfilled AccountUUID, got %q", fp2.AccountUUID)
	}
	if fp2.DeviceID != fp1.DeviceID {
		t.Errorf("DeviceID must stay stable across backfill")
	}
}

func TestGetOrCreateOAuthFingerprint_NilAuth(t *testing.T) {
	store := NewMemoryFingerprintStore(0)
	fp, err := GetOrCreateOAuthFingerprint(context.Background(), store, nil, nil)
	if err != nil || fp != nil {
		t.Errorf("expected nil fp for nil auth, got %+v err=%v", fp, err)
	}
}

func TestGetOrCreateOAuthFingerprint_EmptyAccountID(t *testing.T) {
	store := NewMemoryFingerprintStore(time.Hour)
	auth := &cliproxyauth.Auth{ID: ""}
	fp, _ := GetOrCreateOAuthFingerprint(context.Background(), store, auth, nil)
	if fp == nil || fp.DeviceID == "" {
		t.Fatal("expected ephemeral fingerprint with deviceID")
	}
	// Empty key should never land in the store.
	if _, ok, _ := store.Get(context.Background(), ""); ok {
		t.Error("empty accountID should not populate store")
	}
}

type errStore struct{}

func (errStore) Get(context.Context, string) (*OAuthFingerprint, bool, error) {
	return nil, false, errors.New("boom")
}
func (errStore) Set(context.Context, string, *OAuthFingerprint) error {
	return errors.New("boom")
}

func TestGetOrCreateOAuthFingerprint_PropagatesCacheErrorsThroughHook(t *testing.T) {
	var seen []error
	hook := func(err error) { seen = append(seen, err) }
	auth := &cliproxyauth.Auth{ID: "acct"}
	fp, err := GetOrCreateOAuthFingerprint(context.Background(), errStore{}, auth, hook)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if fp == nil || fp.DeviceID == "" {
		t.Fatal("expected fallback fingerprint despite cache errors")
	}
	if len(seen) == 0 {
		t.Error("expected onCacheError to fire")
	}
}
