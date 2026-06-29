package helps

import (
	"net/http"
	"testing"
)

func TestSetHeaderRaw_PreservesWireCasing(t *testing.T) {
	h := http.Header{}
	// http.Header.Set would canonicalise to "X-Stainless-Os".
	SetHeaderRaw(h, "X-Stainless-OS", "MacOS")
	if _, ok := h["X-Stainless-OS"]; !ok {
		t.Fatalf("expected X-Stainless-OS key, got %#v", h)
	}
	if _, ok := h["X-Stainless-Os"]; ok {
		t.Errorf("canonical form leaked: %#v", h)
	}
	if v := h["X-Stainless-OS"][0]; v != "MacOS" {
		t.Errorf("value mismatch: %s", v)
	}
}

func TestSetHeaderRaw_RemovesAllPriorSpellings(t *testing.T) {
	h := http.Header{}
	h["X-Stainless-Os"] = []string{"Linux"}  // canonical (Go default)
	h["X-Stainless-OS"] = []string{"oldval"} // wire
	SetHeaderRaw(h, "X-Stainless-OS", "MacOS")
	if len(h["X-Stainless-OS"]) != 1 || h["X-Stainless-OS"][0] != "MacOS" {
		t.Errorf("expected single MacOS entry, got %#v", h)
	}
	if _, ok := h["X-Stainless-Os"]; ok {
		t.Errorf("canonical spelling not deleted: %#v", h)
	}
}

func TestSetHeaderRaw_LowercaseAnthropicBeta(t *testing.T) {
	h := http.Header{}
	h["Anthropic-Beta"] = []string{"old"}
	SetHeaderRaw(h, "anthropic-beta", "claude-code-20250219")
	if _, ok := h["Anthropic-Beta"]; ok {
		t.Errorf("canonical Anthropic-Beta leaked: %#v", h)
	}
	if v, ok := h["anthropic-beta"]; !ok || v[0] != "claude-code-20250219" {
		t.Errorf("expected lowercase anthropic-beta, got %#v", h)
	}
}

func TestDeleteHeaderAllForms(t *testing.T) {
	h := http.Header{}
	h["X-Stainless-Os"] = []string{"Linux"}
	h["X-Stainless-OS"] = []string{"MacOS"}
	DeleteHeaderAllForms(h, "X-Stainless-OS")
	if len(h) != 0 {
		t.Errorf("expected all spellings removed, got %#v", h)
	}
}

func TestResolveHeaderWireCasing_Defaults(t *testing.T) {
	cases := map[string]string{
		"X-Stainless-OS":   "X-Stainless-OS",
		"x-stainless-os":   "X-Stainless-OS",
		"X-Stainless-Os":   "X-Stainless-OS",
		"anthropic-beta":   "anthropic-beta",
		"Anthropic-Beta":   "anthropic-beta",
		"User-Agent":       "User-Agent",
		"x-unknown-custom": "x-unknown-custom",
	}
	for in, want := range cases {
		if got := ResolveHeaderWireCasing(in); got != want {
			t.Errorf("ResolveHeaderWireCasing(%q) = %q, want %q", in, got, want)
		}
	}
}
