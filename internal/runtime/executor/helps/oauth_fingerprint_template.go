package helps

// TemplateCLIVersion is the Claude Code CLI version pinned by the OAuth mimicry
// pipeline. The User-Agent, anthropic-beta token list, and metadata.user_id JSON
// format are tied to this constant; update them together.
const TemplateCLIVersion = "2.1.195"

// TemplateUserAgent matches the wire format produced by the real Claude Code
// CLI of TemplateCLIVersion.
const TemplateUserAgent = "claude-cli/" + TemplateCLIVersion + " (external, cli)"

// TemplateAnthropicBeta lists every beta token the official Claude Code CLI of
// TemplateCLIVersion attaches to /v1/messages requests. Replacing this verbatim
// avoids the "client sent inconsistent beta tokens" third-party heuristic.
const TemplateAnthropicBeta = "claude-code-20250219," +
	"interleaved-thinking-2025-05-14," +
	"redact-thinking-2026-02-12," +
	"thinking-token-count-2026-05-13," +
	"context-management-2025-06-27," +
	"prompt-caching-scope-2026-01-05," +
	"effort-2025-11-24"

// TemplateAnthropicVersion is the Anthropic-Version header value used by the
// pinned CLI build.
const TemplateAnthropicVersion = "2023-06-01"

// TemplateXApp matches the x-app header value used by the pinned CLI build.
const TemplateXApp = "cli"

// TemplateAnthropicDangerousDirectBrowserAccess matches the bypass header value
// used by the pinned CLI build.
const TemplateAnthropicDangerousDirectBrowserAccess = "true"

// FingerprintTemplate is the wire-level header baseline for TemplateCLIVersion.
// GetOrCreateOAuthFingerprint copies this template and stamps it with the
// account-specific identifiers.
var FingerprintTemplate = OAuthFingerprint{
	UserAgent:               TemplateUserAgent,
	StainlessArch:           "arm64",
	StainlessLang:           "js",
	StainlessOS:             "MacOS",
	StainlessPackageVersion: "0.94.0",
	StainlessRuntime:        "node",
	StainlessRuntimeVersion: "v26.3.0",
	StainlessRetryCount:     "0",
	StainlessTimeout:        "300",
}
