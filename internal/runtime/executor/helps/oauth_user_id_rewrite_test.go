package helps

import (
	"strings"
	"testing"

	"github.com/tidwall/gjson"
)

func TestRewriteOAuthUserID_StableDerivation(t *testing.T) {
	body := []byte(`{"metadata":{"user_id":"{\"device_id\":\"olddev\",\"account_uuid\":\"\",\"session_id\":\"orig-session\"}"}}`)
	out1 := RewriteOAuthUserID(body, "account-1", "acc-uuid", "newdev", "2.1.195")
	out2 := RewriteOAuthUserID(body, "account-1", "acc-uuid", "newdev", "2.1.195")
	if string(out1) != string(out2) {
		t.Fatalf("rewrite should be deterministic for the same account+session: %s vs %s", out1, out2)
	}

	uid := gjson.GetBytes(out1, "metadata.user_id").String()
	parsed := ParseMetadataUserID(uid)
	if parsed == nil {
		t.Fatalf("rewritten user_id is unparsable: %s", uid)
	}
	if parsed.DeviceID != "newdev" || parsed.AccountUUID != "acc-uuid" {
		t.Errorf("expected device_id/account_uuid replaced: %+v", parsed)
	}
	if parsed.SessionID == "" || parsed.SessionID == "orig-session" {
		t.Errorf("session_id should be derived, got %q", parsed.SessionID)
	}
	if !parsed.IsNewFormat {
		t.Error("expected JSON format for 2.1.195")
	}
}

func TestRewriteOAuthUserID_AccountIsolation(t *testing.T) {
	body := []byte(`{"metadata":{"user_id":"{\"device_id\":\"d\",\"account_uuid\":\"\",\"session_id\":\"same-session\"}"}}`)
	outA := RewriteOAuthUserID(body, "account-A", "", "dev", "2.1.195")
	outB := RewriteOAuthUserID(body, "account-B", "", "dev", "2.1.195")
	sessA := ParseMetadataUserID(gjson.GetBytes(outA, "metadata.user_id").String()).SessionID
	sessB := ParseMetadataUserID(gjson.GetBytes(outB, "metadata.user_id").String()).SessionID
	if sessA == sessB {
		t.Fatalf("different accounts must yield different sessions, both = %s", sessA)
	}
}

func TestRewriteOAuthUserID_MissingMetadata(t *testing.T) {
	body := []byte(`{"model":"claude-sonnet-4-6","messages":[]}`)
	out := RewriteOAuthUserID(body, "account-1", "acc", "dev", "2.1.195")
	uid := gjson.GetBytes(out, "metadata.user_id").String()
	if uid == "" {
		t.Fatal("expected metadata.user_id to be injected when missing")
	}
	parsed := ParseMetadataUserID(uid)
	if parsed == nil || parsed.DeviceID != "dev" {
		t.Errorf("expected fingerprint deviceID, got %+v", parsed)
	}
}

func TestRewriteOAuthUserID_BodyFingerprintFallback(t *testing.T) {
	// metadata exists but user_id is unparseable. Two identical bodies should
	// still produce the same session id within the same account.
	body := []byte(`{"metadata":{"user_id":"garbage","foo":"bar"}}`)
	out1 := RewriteOAuthUserID(body, "account-1", "", "dev", "2.1.195")
	out2 := RewriteOAuthUserID(body, "account-1", "", "dev", "2.1.195")
	if string(out1) != string(out2) {
		t.Fatalf("body-fingerprint fallback must be stable: %s vs %s", out1, out2)
	}
}

func TestRewriteOAuthUserID_LegacyOutputForOldVersion(t *testing.T) {
	body := []byte(`{"metadata":{"user_id":"x"}}`)
	out := RewriteOAuthUserID(body, "account-1", "", "dev", "2.1.0")
	uid := gjson.GetBytes(out, "metadata.user_id").String()
	if !strings.HasPrefix(uid, "user_dev_account__session_") {
		t.Errorf("expected legacy form for old version, got %s", uid)
	}
}

func TestRewriteOAuthUserID_EmptyDeviceIDIsNoop(t *testing.T) {
	body := []byte(`{"metadata":{"user_id":"x"}}`)
	out := RewriteOAuthUserID(body, "account-1", "", "", "2.1.195")
	if string(out) != string(body) {
		t.Errorf("expected no-op when deviceID empty")
	}
}
