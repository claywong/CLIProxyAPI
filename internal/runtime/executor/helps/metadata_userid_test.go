package helps

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseMetadataUserID_JSON(t *testing.T) {
	raw := `{"device_id":"dev123","account_uuid":"acc-uuid","session_id":"2b84a352-60dd-45a3-a028-a75de7f0b1c2"}`
	parsed := ParseMetadataUserID(raw)
	if parsed == nil {
		t.Fatal("expected ParseMetadataUserID to succeed")
	}
	if !parsed.IsNewFormat {
		t.Error("expected IsNewFormat=true for JSON input")
	}
	if parsed.DeviceID != "dev123" || parsed.AccountUUID != "acc-uuid" || parsed.SessionID != "2b84a352-60dd-45a3-a028-a75de7f0b1c2" {
		t.Errorf("parsed mismatch: %+v", parsed)
	}
}

func TestParseMetadataUserID_Legacy(t *testing.T) {
	hex64 := strings.Repeat("ab", 32)
	raw := "user_" + hex64 + "_account_2b84a352-60dd-45a3-a028-a75de7f0b1c2_session_3c84a352-60dd-45a3-a028-a75de7f0b1c3"
	parsed := ParseMetadataUserID(raw)
	if parsed == nil {
		t.Fatal("expected ParseMetadataUserID to succeed for legacy form")
	}
	if parsed.IsNewFormat {
		t.Error("expected IsNewFormat=false for legacy input")
	}
	if parsed.DeviceID != hex64 {
		t.Errorf("DeviceID mismatch: %s", parsed.DeviceID)
	}
}

func TestParseMetadataUserID_Invalid(t *testing.T) {
	for _, raw := range []string{"", "garbage", "{}", `{"device_id":"x"}`, "user_short_account_x_session_y"} {
		if parsed := ParseMetadataUserID(raw); parsed != nil {
			t.Errorf("expected nil for %q, got %+v", raw, parsed)
		}
	}
}

func TestFormatMetadataUserID_JSONForNewVersion(t *testing.T) {
	out := FormatMetadataUserID("dev", "acc", "ses", "2.1.195")
	if !strings.HasPrefix(out, "{") {
		t.Fatalf("expected JSON output for new version, got %s", out)
	}
	var j struct {
		DeviceID    string `json:"device_id"`
		AccountUUID string `json:"account_uuid"`
		SessionID   string `json:"session_id"`
	}
	if err := json.Unmarshal([]byte(out), &j); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if j.DeviceID != "dev" || j.AccountUUID != "acc" || j.SessionID != "ses" {
		t.Errorf("JSON fields mismatch: %+v", j)
	}
}

func TestFormatMetadataUserID_LegacyForOldVersion(t *testing.T) {
	out := FormatMetadataUserID("dev", "acc", "ses", "2.1.50")
	want := "user_dev_account_acc_session_ses"
	if out != want {
		t.Errorf("legacy format mismatch: want %s, got %s", want, out)
	}
}

func TestFormatMetadataUserID_LegacyForEmptyVersion(t *testing.T) {
	out := FormatMetadataUserID("dev", "acc", "ses", "")
	if !strings.HasPrefix(out, "user_") {
		t.Errorf("expected legacy form for empty version, got %s", out)
	}
}

func TestIsNewMetadataFormatVersion(t *testing.T) {
	cases := map[string]bool{
		"":        false,
		"2.1.77":  false,
		"2.1.78":  true,
		"2.1.195": true,
		"2.2.0":   true,
		"1.9.999": false,
	}
	for v, want := range cases {
		if got := IsNewMetadataFormatVersion(v); got != want {
			t.Errorf("IsNewMetadataFormatVersion(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestExtractCLIVersion(t *testing.T) {
	cases := map[string]string{
		"claude-cli/2.1.195 (external, cli)": "2.1.195",
		"claude-cli/2.1.78":                  "2.1.78",
		"":                                   "",
		"openai/4.0.0":                       "",
	}
	for ua, want := range cases {
		if got := ExtractCLIVersion(ua); got != want {
			t.Errorf("ExtractCLIVersion(%q) = %q, want %q", ua, got, want)
		}
	}
}
