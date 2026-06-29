package helps

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"
)

// oauthMimicryHeaderNames lists every wire header the OAuth mimicry pipeline
// owns. The pipeline always clears these in every spelling before stamping the
// template values, so downstream client headers never leak through.
var oauthMimicryHeaderNames = []string{
	"User-Agent",
	"Accept",
	"X-Stainless-Lang",
	"X-Stainless-Package-Version",
	"X-Stainless-OS",
	"X-Stainless-Arch",
	"X-Stainless-Runtime",
	"X-Stainless-Runtime-Version",
	"X-Stainless-Retry-Count",
	"X-Stainless-Timeout",
	"x-stainless-helper-method",
	"anthropic-beta",
	"anthropic-version",
	"anthropic-dangerous-direct-browser-access",
	"x-app",
	"x-client-request-id",
	"X-Claude-Code-Session-Id",
}

// ApplyOAuthMimicryHeaders deletes every client-supplied identity header and
// rewrites them with the fingerprint template values. x-client-request-id is
// regenerated per call. When isStream is true the helper-method header is
// stamped with "stream" to match the real CLI's streaming requests.
func ApplyOAuthMimicryHeaders(req *http.Request, fp *OAuthFingerprint, isStream bool) {
	if req == nil || fp == nil {
		return
	}

	for _, name := range oauthMimicryHeaderNames {
		DeleteHeaderAllForms(req.Header, name)
	}

	SetHeaderRaw(req.Header, "Accept", "application/json")
	SetHeaderRaw(req.Header, "User-Agent", fp.UserAgent)
	SetHeaderRaw(req.Header, "X-Stainless-Lang", fp.StainlessLang)
	SetHeaderRaw(req.Header, "X-Stainless-Package-Version", fp.StainlessPackageVersion)
	SetHeaderRaw(req.Header, "X-Stainless-OS", fp.StainlessOS)
	SetHeaderRaw(req.Header, "X-Stainless-Arch", fp.StainlessArch)
	SetHeaderRaw(req.Header, "X-Stainless-Runtime", fp.StainlessRuntime)
	SetHeaderRaw(req.Header, "X-Stainless-Runtime-Version", fp.StainlessRuntimeVersion)
	SetHeaderRaw(req.Header, "X-Stainless-Retry-Count", fp.StainlessRetryCount)
	SetHeaderRaw(req.Header, "X-Stainless-Timeout", fp.StainlessTimeout)
	SetHeaderRaw(req.Header, "x-app", TemplateXApp)
	SetHeaderRaw(req.Header, "anthropic-dangerous-direct-browser-access", TemplateAnthropicDangerousDirectBrowserAccess)
	SetHeaderRaw(req.Header, "anthropic-version", TemplateAnthropicVersion)
	SetHeaderRaw(req.Header, "anthropic-beta", TemplateAnthropicBeta)

	if isStream {
		SetHeaderRaw(req.Header, "x-stainless-helper-method", "stream")
	}
	SetHeaderRaw(req.Header, "x-client-request-id", uuid.New().String())
}

// SyncOAuthSessionHeader copies the session_id embedded in metadata.user_id
// onto the X-Claude-Code-Session-Id header, ensuring the wire header matches
// the body view of the session. Bodies without a parsable user_id leave the
// header untouched (the caller may have set a fallback already).
func SyncOAuthSessionHeader(req *http.Request, body []byte) {
	if req == nil {
		return
	}
	uid := gjson.GetBytes(body, "metadata.user_id").String()
	if uid == "" {
		return
	}
	parsed := ParseMetadataUserID(uid)
	if parsed == nil || parsed.SessionID == "" {
		return
	}
	SetHeaderRaw(req.Header, "X-Claude-Code-Session-Id", parsed.SessionID)
}
