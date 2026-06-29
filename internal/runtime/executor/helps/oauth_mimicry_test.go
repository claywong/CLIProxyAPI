package helps

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func newReq() *http.Request {
	u, _ := url.Parse("https://api.anthropic.com/v1/messages")
	return &http.Request{Method: http.MethodPost, URL: u, Header: http.Header{}}
}

func TestApplyOAuthMimicryHeaders_OverwritesClientValues(t *testing.T) {
	req := newReq()
	// Simulate client-leaked values across multiple spellings.
	req.Header["User-Agent"] = []string{"opencode/1.0"}
	req.Header["X-Stainless-Os"] = []string{"Linux"}
	req.Header["anthropic-beta"] = []string{"client-injected"}
	req.Header["X-App"] = []string{"sdk"}

	fp := FingerprintTemplate
	fp.DeviceID = strings.Repeat("a", 64)
	fp.AccountID = "acct-1"
	ApplyOAuthMimicryHeaders(req, &fp, false)

	if got := req.Header.Get("User-Agent"); got != TemplateUserAgent {
		t.Errorf("User-Agent not overridden: %s", got)
	}
	if _, ok := req.Header["X-Stainless-Os"]; ok {
		t.Errorf("canonical X-Stainless-Os should be removed")
	}
	if _, ok := req.Header["X-Stainless-OS"]; !ok {
		t.Errorf("wire X-Stainless-OS missing")
	}
	if v := req.Header["anthropic-beta"]; len(v) != 1 || v[0] != TemplateAnthropicBeta {
		t.Errorf("anthropic-beta override failed: %#v", v)
	}
	if v := req.Header["x-app"]; len(v) != 1 || v[0] != TemplateXApp {
		t.Errorf("x-app not stamped: %#v", v)
	}
	if v := req.Header["x-client-request-id"]; len(v) != 1 || v[0] == "" {
		t.Errorf("x-client-request-id missing: %#v", v)
	}
	if _, ok := req.Header["x-stainless-helper-method"]; ok {
		t.Errorf("helper-method should be absent for non-stream calls")
	}
}

func TestApplyOAuthMimicryHeaders_StreamStampsHelperMethod(t *testing.T) {
	req := newReq()
	fp := FingerprintTemplate
	ApplyOAuthMimicryHeaders(req, &fp, true)
	if v := req.Header["x-stainless-helper-method"]; len(v) != 1 || v[0] != "stream" {
		t.Errorf("expected stream helper-method, got %#v", v)
	}
}

func TestSyncOAuthSessionHeader_UsesBodySessionID(t *testing.T) {
	req := newReq()
	body := []byte(`{"metadata":{"user_id":"{\"device_id\":\"d\",\"account_uuid\":\"\",\"session_id\":\"abc-session\"}"}}`)
	SyncOAuthSessionHeader(req, body)
	if v := req.Header["X-Claude-Code-Session-Id"]; len(v) != 1 || v[0] != "abc-session" {
		t.Errorf("session header mismatch: %#v", v)
	}
}

func TestSyncOAuthSessionHeader_NoUserIDIsNoop(t *testing.T) {
	req := newReq()
	req.Header.Set("X-Claude-Code-Session-Id", "preset")
	SyncOAuthSessionHeader(req, []byte(`{"messages":[]}`))
	if v := req.Header.Get("X-Claude-Code-Session-Id"); v != "preset" {
		t.Errorf("expected preset value to be preserved, got %s", v)
	}
}
