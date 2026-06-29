package helps

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

// NewMetadataFormatMinVersion is the lowest Claude Code CLI version that emits
// metadata.user_id as a JSON document. Older builds keep the legacy
// "user_<hex>_account_<uuid>_session_<uuid>" concatenated form.
const NewMetadataFormatMinVersion = "2.1.78"

// ParsedUserID describes the components extracted from a metadata.user_id value.
// IsNewFormat is true when the raw input parsed as the JSON variant.
type ParsedUserID struct {
	DeviceID    string
	AccountUUID string
	SessionID   string
	IsNewFormat bool
}

// legacyUserIDRegex matches user_<64-hex>_account_<optional-uuid>_session_<uuid>.
var legacyUserIDRegex = regexp.MustCompile(
	`^user_([a-fA-F0-9]{64})_account_([a-fA-F0-9-]*)_session_([a-fA-F0-9-]{36})$`)

// jsonUserID is the JSON representation used by Claude Code CLI >= 2.1.78.
type jsonUserID struct {
	DeviceID    string `json:"device_id"`
	AccountUUID string `json:"account_uuid"`
	SessionID   string `json:"session_id"`
}

// ParseMetadataUserID accepts either the legacy concatenated form or the new
// JSON variant and returns nil when the input is unrecognised. The JSON form
// requires at least device_id and session_id to be considered valid.
func ParseMetadataUserID(raw string) *ParsedUserID {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if raw[0] == '{' {
		var j jsonUserID
		if err := json.Unmarshal([]byte(raw), &j); err != nil {
			return nil
		}
		if j.DeviceID == "" || j.SessionID == "" {
			return nil
		}
		return &ParsedUserID{
			DeviceID:    j.DeviceID,
			AccountUUID: j.AccountUUID,
			SessionID:   j.SessionID,
			IsNewFormat: true,
		}
	}
	matches := legacyUserIDRegex.FindStringSubmatch(raw)
	if matches == nil {
		return nil
	}
	return &ParsedUserID{
		DeviceID:    matches[1],
		AccountUUID: matches[2],
		SessionID:   matches[3],
		IsNewFormat: false,
	}
}

// FormatMetadataUserID renders the supplied components in the format expected
// by the given Claude Code CLI uaVersion. Versions >= NewMetadataFormatMinVersion
// emit the JSON representation, older builds fall back to the legacy form.
func FormatMetadataUserID(deviceID, accountUUID, sessionID, uaVersion string) string {
	if IsNewMetadataFormatVersion(uaVersion) {
		b, _ := json.Marshal(jsonUserID{
			DeviceID:    deviceID,
			AccountUUID: accountUUID,
			SessionID:   sessionID,
		})
		return string(b)
	}
	return "user_" + deviceID + "_account_" + accountUUID + "_session_" + sessionID
}

// IsNewMetadataFormatVersion reports whether the given version string is >=
// NewMetadataFormatMinVersion. An empty or unparsable version returns false.
func IsNewMetadataFormatVersion(version string) bool {
	if strings.TrimSpace(version) == "" {
		return false
	}
	return compareSemver(version, NewMetadataFormatMinVersion) >= 0
}

// claudeCodeUAVersionPattern extracts the version segment from a Claude Code UA
// string such as "claude-cli/2.1.195 (external, cli)".
var claudeCodeUAVersionPattern = regexp.MustCompile(`claude-cli/([0-9]+(?:\.[0-9]+){0,3})`)

// ExtractCLIVersion returns the version segment from a Claude Code UA. Returns
// "" when the pattern does not match.
func ExtractCLIVersion(ua string) string {
	matches := claudeCodeUAVersionPattern.FindStringSubmatch(ua)
	if len(matches) >= 2 {
		return matches[1]
	}
	return ""
}

// compareSemver compares dotted version strings component-wise. Missing
// components are treated as 0. Non-numeric segments lexicographically compare
// as zero so the caller can keep using simple numeric versions.
func compareSemver(a, b string) int {
	pa := strings.Split(a, ".")
	pb := strings.Split(b, ".")
	max := len(pa)
	if len(pb) > max {
		max = len(pb)
	}
	for i := 0; i < max; i++ {
		var ia, ib int
		if i < len(pa) {
			ia, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			ib, _ = strconv.Atoi(pb[i])
		}
		switch {
		case ia < ib:
			return -1
		case ia > ib:
			return 1
		}
	}
	return 0
}
