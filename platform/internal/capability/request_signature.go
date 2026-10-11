package capability

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// requestSignaturePayload binds an operation and its exact payload, not only bytes.
// 请求签名绑定操作与精确正文，阻止签名跨公共能力入口重放。
func requestSignaturePayload(method, target string, body []byte) []byte {
	digest := sha256.Sum256(body)
	// Fixed strings cannot fail encoding; disable HTML escaping for Python parity.
	var output strings.Builder
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode([4]string{"platform-capability/v2", strings.ToUpper(method), target, hex.EncodeToString(digest[:])})
	return []byte(strings.TrimSuffix(output.String(), "\n"))
}
