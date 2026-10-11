// Package planloader loads the immutable mapping plan from a registered,
// signed document and keeps the last-known-good (LKG) revision when a refresh
// fails, so a bad or missing plan can never take a running adapter offline.
// planloader 包从已登记且已签名的文档加载不可变映射计划，并在刷新失败时保留上一个
// 已知可用（LKG）版本，使坏计划或暂时读不到的计划都不会让运行中的 Adapter 下线。
package planloader

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sync"

	"github.com/lexagent/legacy-http-adapter/internal/mapping"
)

var (
	// ErrEnvelopeInvalid means the signed document is not a plan envelope.
	// ErrEnvelopeInvalid 表示签名文档不是合法的计划信封。
	ErrEnvelopeInvalid = errors.New("signed plan envelope is invalid")
	// ErrSignatureInvalid means the plan was not signed by the pinned key.
	// ErrSignatureInvalid 表示计划不是由固定公钥签名的。
	ErrSignatureInvalid = errors.New("mapping plan signature is invalid")
	// ErrRevisionRollback means the plan revision went backwards.
	// ErrRevisionRollback 表示计划版本发生回退。
	ErrRevisionRollback = errors.New("mapping plan revision rolled back")
	// ErrNoPlan means no revision has ever loaded successfully.
	// ErrNoPlan 表示从未成功加载过任何版本。
	ErrNoPlan = errors.New("no mapping plan has been loaded yet")
)

// Loader owns one plan document. Every refresh either advances the LKG or
// leaves it untouched; it never clears a good plan because a newer read failed.
// Loader 管理一份计划文档。每次刷新要么推进 LKG，要么原样保留；绝不会因为一次
// 读取失败而清空可用计划。
type Loader struct {
	Path         string
	PublicKey    ed25519.PublicKey
	ExpectedHash string
	MinRevision  uint64

	mu       sync.RWMutex
	current  *mapping.Plan
	digest   string
	degraded bool
	lastErr  error
}

// Refresh re-reads and re-verifies the document. On success it becomes the LKG.
// On failure the previous LKG is returned with a non-nil error and the loader
// is marked degraded, which is exactly the "refresh failure keeps the LKG"
// contract the platform relies on. / Refresh 重新读取并校验文档：成功即成为 LKG；
// 失败则返回原 LKG 与非 nil 错误并标记为 degraded——这正是平台依赖的
// 「刷新失败保留 LKG」契约。
func (l *Loader) Refresh() (mapping.Plan, error) {
	if l.Path == "" {
		return l.fail(ErrNoPlan)
	}
	raw, err := os.ReadFile(l.Path)
	if err != nil {
		return l.fail(err)
	}
	plan, digest, err := l.verify(raw)
	if err != nil {
		return l.fail(err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.current != nil && plan.Revision < l.current.Revision {
		return *l.current, ErrRevisionRollback
	}
	l.current = &plan
	l.digest = digest
	l.degraded = false
	l.lastErr = nil
	return plan, nil
}

// fail records the failure and returns the LKG together with the error. When no
// revision has ever loaded there is no LKG to fall back to, so the error stands
// alone and callers must refuse the request.
// fail 记录失败并连同错误一起返回 LKG。若从未成功加载过任何版本则无可回退的 LKG，
// 错误独立返回，调用方必须拒绝该请求。
func (l *Loader) fail(cause error) (mapping.Plan, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lastErr = cause
	if l.current == nil {
		return mapping.Plan{}, cause
	}
	l.degraded = true
	return *l.current, cause
}

// Current returns the LKG plan. ok is false until the first successful load.
// Current 返回 LKG 计划；首次成功加载前 ok 为 false。
func (l *Loader) Current() (mapping.Plan, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.current == nil {
		return mapping.Plan{}, false
	}
	return *l.current, true
}

// Degraded reports whether the most recent refresh failed while an LKG was kept.
// Degraded 表示最近一次刷新失败但已保留 LKG。
func (l *Loader) Degraded() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.degraded
}

// Revision returns the LKG revision, or zero before the first load.
// Revision 返回 LKG 版本；首次加载前为 0。
func (l *Loader) Revision() uint64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.current == nil {
		return 0
	}
	return l.current.Revision
}

// Digest returns the hex SHA-256 of the plan bytes, the evidence that the
// loaded revision is byte-for-byte the published one.
// Digest 返回计划字节的十六进制 SHA-256，作为「所加载版本与已发布版本逐字节一致」的证据。
func (l *Loader) Digest() string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.digest
}

// verify enforces, in order, the signature, the pinned hash and the grammar, so
// an unsigned, tampered or malformed plan never reaches the interpreter.
// verify 依次强制签名、固定哈希与语法，使未签名、被篡改或畸形的计划永远到不了解释器。
func (l *Loader) verify(raw []byte) (mapping.Plan, string, error) {
	body := raw
	if len(l.PublicKey) > 0 {
		var envelope struct {
			Signature string          `json:"signature"`
			Plan      json.RawMessage `json:"plan"`
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if dec.Decode(&envelope) != nil || envelope.Signature == "" || len(envelope.Plan) == 0 {
			return mapping.Plan{}, "", ErrEnvelopeInvalid
		}
		signature, err := base64.StdEncoding.DecodeString(envelope.Signature)
		if err != nil || !ed25519.Verify(l.PublicKey, envelope.Plan, signature) {
			return mapping.Plan{}, "", ErrSignatureInvalid
		}
		// The interpreter sees exactly the signed bytes, never the envelope.
		// 解释器只看到被签名的字节，而不是整个信封。
		body = envelope.Plan
	}
	plan, err := mapping.DecodeWirePlanBody(body, l.ExpectedHash)
	if err != nil {
		return mapping.Plan{}, "", err
	}
	if plan.Revision < l.MinRevision {
		return mapping.Plan{}, "", ErrRevisionRollback
	}
	sum := sha256.Sum256(body)
	return *plan, hex.EncodeToString(sum[:]), nil
}
