package helps

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// RewriteOAuthUserID rebuilds metadata.user_id so that:
//   - device_id is replaced with the stable per-account fingerprint;
//   - account_uuid comes from the auth record;
//   - session_id is a UUID derived from SHA256(accountID :: originalSession).
//
// The output format is selected by uaVersion. When the body has no metadata
// object yet, one is created. When the original metadata.user_id is missing
// or cannot be parsed, a new session is seeded from a body fingerprint so the
// same payload yields the same session id within the account.
func RewriteOAuthUserID(body []byte, accountID, accountUUID, deviceID, uaVersion string) []byte {
	if len(body) == 0 || deviceID == "" {
		return body
	}

	metadata := gjson.GetBytes(body, "metadata")
	hasMetadata := metadata.Exists() && metadata.Type == gjson.JSON

	var origSession string
	if hasMetadata {
		if origUserID := gjson.GetBytes(body, "metadata.user_id").String(); origUserID != "" {
			if parsed := ParseMetadataUserID(origUserID); parsed != nil && parsed.SessionID != "" {
				origSession = parsed.SessionID
			}
		}
	}
	if origSession == "" {
		// Fallback: derive a session seed from a stable body fingerprint so
		// repeated calls with the same body land on the same session id.
		origSession = stableBodyDigest(body)
	}

	seed := fmt.Sprintf("%s::%s", accountID, origSession)
	newSession := uuidFromSeed(seed)

	newUserID := FormatMetadataUserID(deviceID, accountUUID, newSession, uaVersion)
	newBody, err := sjson.SetBytes(body, "metadata.user_id", newUserID)
	if err != nil {
		return body
	}
	return newBody
}

// uuidFromSeed maps an arbitrary seed string to a deterministic UUID v4 string.
// The first 16 bytes of SHA256(seed) form the UUID; the standard version (4)
// and variant (RFC 4122) bits are forced so downstream consumers see a
// well-formed UUID.
func uuidFromSeed(seed string) string {
	digest := sha256.Sum256([]byte(seed))
	var u uuid.UUID
	copy(u[:], digest[:16])
	u[6] = (u[6] & 0x0f) | 0x40
	u[8] = (u[8] & 0x3f) | 0x80
	return u.String()
}

// stableBodyDigest hashes the entire request body and returns a hex digest.
// Used as the session seed when the incoming payload has no parsable user_id.
func stableBodyDigest(body []byte) string {
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}
