package helps

import (
	"net/http"
	"strings"
)

// headerWireCasing pins every header that downstream Claude OAuth requests need
// to send with a specific casing. Go's net/http canonicalises keys on read
// (X-Stainless-Os instead of X-Stainless-OS), which Anthropic uses as a
// third-party detection signal; SetHeaderRaw restores the exact wire format.
var headerWireCasing = map[string]string{
	"accept":     "Accept",
	"user-agent": "User-Agent",

	// X-Stainless-* preserves the casing the Anthropic SDK actually emits.
	"x-stainless-retry-count":     "X-Stainless-Retry-Count",
	"x-stainless-timeout":         "X-Stainless-Timeout",
	"x-stainless-lang":            "X-Stainless-Lang",
	"x-stainless-package-version": "X-Stainless-Package-Version",
	"x-stainless-os":              "X-Stainless-OS",
	"x-stainless-arch":            "X-Stainless-Arch",
	"x-stainless-runtime":         "X-Stainless-Runtime",
	"x-stainless-runtime-version": "X-Stainless-Runtime-Version",
	"x-stainless-helper-method":   "x-stainless-helper-method",

	// All-lowercase, as the SDK emits them on the wire.
	"anthropic-dangerous-direct-browser-access": "anthropic-dangerous-direct-browser-access",
	"anthropic-version":                         "anthropic-version",
	"anthropic-beta":                            "anthropic-beta",
	"x-app":                                     "x-app",
	"content-type":                              "content-type",
	"accept-encoding":                           "accept-encoding",
	"authorization":                             "authorization",

	"x-claude-code-session-id": "X-Claude-Code-Session-Id",
	"x-client-request-id":      "x-client-request-id",
	"content-length":           "content-length",
}

// ResolveHeaderWireCasing returns the wire-format key for the given header
// name. Unknown keys are returned unchanged.
func ResolveHeaderWireCasing(key string) string {
	if wk, ok := headerWireCasing[strings.ToLower(key)]; ok {
		return wk
	}
	return key
}

// SetHeaderRaw stores a header with the exact wire casing while clearing any
// previous canonical / wire / raw spellings to avoid duplicate sends.
func SetHeaderRaw(h http.Header, key, value string) {
	if h == nil || key == "" {
		return
	}
	h.Del(key)
	wk := ResolveHeaderWireCasing(key)
	if wk != key {
		delete(h, wk)
	}
	delete(h, key)
	target := wk
	if target == "" {
		target = key
	}
	h[target] = []string{value}
}

// DeleteHeaderAllForms removes a header under its canonical, wire-cased, and
// raw spellings so a subsequent SetHeaderRaw cannot coexist with a passthrough
// value left over from earlier middleware.
func DeleteHeaderAllForms(h http.Header, key string) {
	if h == nil || key == "" {
		return
	}
	h.Del(key)
	delete(h, key)
	if wk := ResolveHeaderWireCasing(key); wk != key {
		delete(h, wk)
	}
}
