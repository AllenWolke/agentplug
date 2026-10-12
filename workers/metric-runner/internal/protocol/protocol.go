// Package protocol defines the signed, pre-registered metric plugin loading
// protocol shared by the metric runner and its launcher. A plugin is never
// addressed by a path or an argument supplied on the request: the request names
// a registered plugin id, the runner resolves the pre-registered descriptor,
// verifies the descriptor signature and the artifact digest, and only then
// launches the fixed entrypoint. Everything a caller can influence is therefore
// a lookup key, never a command line.
// Package protocol 定义指标 Runner 与其启动方共享的、签名预注册的插件装载协议。
// 插件绝不由请求提供的路径或参数寻址：请求只给出已注册的插件 id，Runner 解析预注册
// 描述符、校验描述符签名与制品摘要，之后才启动固定入口。调用方能影响的一切都只是查表键，
// 绝不是命令行。
package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// DefaultStderrLimit bounds how much plugin stderr is retained for diagnostics.
// DefaultStderrLimit 限定保留多少插件 stderr 用于诊断。
const DefaultStderrLimit = 4 << 10

// MaxDescriptorBytes bounds the descriptor document so a hostile registry entry
// cannot exhaust memory before validation.
// MaxDescriptorBytes 限定描述符文档大小，使恶意注册项在通过校验前无法耗尽内存。
const MaxDescriptorBytes = 64 << 10

var (
	ErrDescriptorInvalid = errors.New("metric plugin descriptor is invalid")
	ErrSignatureInvalid  = errors.New("metric plugin signature is invalid")
	ErrDigestMismatch    = errors.New("metric plugin artifact digest does not match the descriptor")
	ErrEntrypointInvalid = errors.New("metric plugin entrypoint is not a pre-registered absolute path")
	ErrArgsInvalid       = errors.New("metric plugin args are not a fixed, shell-free list")
	ErrPublicKeyMissing  = errors.New("metric plugin public key is not configured")
	ErrPublicKeyInvalid  = errors.New("metric plugin public key is invalid")
	ErrTrailingData      = errors.New("JSON document carries trailing data")
)

// Limits is the immutable resource envelope a descriptor registers for one
// plugin. Every bound must be explicit and positive; an incomplete envelope is
// refused rather than degraded into an unbounded run.
// Limits 是描述符为单个插件登记的不可变资源边界。所有上限必须显式且为正；不完整的
// 信封会被拒绝，而不会退化成无边界执行。
type Limits struct {
	MaxCPUSeconds  int   `json:"max_cpu_seconds"`
	MaxMemoryBytes int64 `json:"max_memory_bytes"`
	MaxPIDs        int   `json:"max_pids"`
	MaxOutputBytes int64 `json:"max_output_bytes"`
	TimeoutSeconds int   `json:"timeout_seconds"`
}

// NetworkNone is the only network mode a metric plugin may register. The runner
// installs a process-level seccomp filter that rejects socket and io_uring
// network operations before the plugin starts, without granting CAP_SYS_ADMIN.
// NetworkNone 是指标插件唯一允许登记的网络模式。Runner 在插件启动前安装进程级 seccomp
// 过滤器，拒绝 socket 与 io_uring 网络操作，且无需授予 CAP_SYS_ADMIN。
const NetworkNone = "none"

// Descriptor is the pre-registered, signed identity of one metric plugin.
// Descriptor 是单个指标插件预注册的、已签名身份。
type Descriptor struct {
	ID         string   `json:"id"`
	Version    string   `json:"version"`
	Entrypoint string   `json:"entrypoint"`
	SHA256     string   `json:"sha256"`
	Signature  string   `json:"signature"`
	Args       []string `json:"args"`
	Network    string   `json:"network"`
	Limits     Limits   `json:"limits"`
}

// shellMeta are the characters that would only matter if something interpolated
// a plugin argument into a shell. The runner always execs an argv vector
// directly and never a shell, but rejecting them keeps the descriptor honest
// about "fixed command/args, no shell concatenation".
// shellMeta 是「只有在把插件参数拼进 shell 时才有意义」的字符。Runner 始终直接 exec
// argv 向量、绝不经过 shell，但拒绝它们能让描述符对「固定 command/args、禁止 shell 拼接」
// 保持诚实。
const shellMeta = ";|&$><`\\\"'\n\r\t"

// DecodeDescriptor strictly decodes one descriptor document. Unknown fields and
// trailing data are rejected so a registry entry can never smuggle extra
// instructions past the reviewed schema.
// DecodeDescriptor 严格解码一份描述符文档。未知字段与尾随数据一律拒绝，使注册项无法
// 绕过已评审的 schema 夹带额外指令。
func DecodeDescriptor(raw []byte) (Descriptor, error) {
	var d Descriptor
	if len(raw) == 0 || len(raw) > MaxDescriptorBytes {
		return d, fmt.Errorf("%w: descriptor size %d", ErrDescriptorInvalid, len(raw))
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return d, fmt.Errorf("%w: %v", ErrDescriptorInvalid, err)
	}
	if err := ensureNoTrailingData(dec); err != nil {
		return d, fmt.Errorf("%w: %v", ErrDescriptorInvalid, err)
	}
	return d, nil
}

// LoadDescriptor reads and strictly decodes a descriptor from disk.
// LoadDescriptor 从磁盘读取并严格解码描述符。
func LoadDescriptor(path string) (Descriptor, error) {
	file, err := os.Open(path)
	if err != nil {
		return Descriptor{}, fmt.Errorf("%w: %v", ErrDescriptorInvalid, err)
	}
	defer file.Close()
	// Enforce the document limit while reading, before decoding or verifying
	// signatures. A corrupt registry entry must not cause an unbounded read.
	raw, err := io.ReadAll(io.LimitReader(file, MaxDescriptorBytes+1))
	if err != nil {
		return Descriptor{}, fmt.Errorf("%w: %v", ErrDescriptorInvalid, err)
	}
	return DecodeDescriptor(raw)
}

// CanonicalBytes returns the deterministic signing payload: the descriptor with
// its signature field cleared, marshalled with a fixed field order. Both the
// signer and the verifier derive it the same way, so a descriptor cannot be
// re-signed over a different byte sequence.
// CanonicalBytes 返回确定性签名载荷：清空签名字段后的描述符，以固定字段顺序序列化。
// 签名方与验证方推导方式一致，因此描述符无法在一段不同的字节序列上被重新签名。
func (d Descriptor) CanonicalBytes() []byte {
	clone := d
	clone.Signature = ""
	raw, err := json.Marshal(clone)
	if err != nil {
		return nil
	}
	return raw
}

// Validate refuses a descriptor that could not be safely executed: a missing
// identity, a relative or traversing entrypoint, a shell-shaped argument list,
// a network mode other than "none", or an incomplete resource envelope.
// Validate 拒绝无法安全执行的描述符：身份缺失、入口为相对路径或含穿越、参数形如 shell
// 片段、网络模式非 "none"、或资源信封不完整。
func (d Descriptor) Validate() error {
	if strings.TrimSpace(d.ID) == "" || strings.TrimSpace(d.Version) == "" {
		return fmt.Errorf("%w: id and version are required", ErrDescriptorInvalid)
	}
	if err := validateEntrypoint(d.Entrypoint); err != nil {
		return err
	}
	if err := validateArgs(d.Args); err != nil {
		return err
	}
	if d.Network != NetworkNone {
		return fmt.Errorf("%w: network must be %q", ErrDescriptorInvalid, NetworkNone)
	}
	if err := d.Limits.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(d.SHA256) == "" || strings.TrimSpace(d.Signature) == "" {
		return fmt.Errorf("%w: digest and signature are required", ErrDescriptorInvalid)
	}
	return nil
}

// Validate refuses a zero-valued envelope on purpose, so a missing registration
// can never be read as "no limits".
// Validate 刻意拒绝零值信封，使缺失的登记永远不会被读成「没有上限」。
func (l Limits) Validate() error {
	if l.MaxCPUSeconds <= 0 || l.MaxMemoryBytes <= 0 || l.MaxPIDs <= 0 || l.MaxOutputBytes <= 0 || l.TimeoutSeconds <= 0 {
		return fmt.Errorf("%w: resource limits must all be positive", ErrDescriptorInvalid)
	}
	return nil
}

func validateEntrypoint(path string) error {
	if !strings.HasPrefix(path, "/") || strings.Contains(path, "..") {
		return fmt.Errorf("%w: %q", ErrEntrypointInvalid, path)
	}
	if strings.ContainsAny(path, shellMeta) {
		return fmt.Errorf("%w: %q", ErrEntrypointInvalid, path)
	}
	return nil
}

func validateArgs(args []string) error {
	for _, arg := range args {
		if strings.ContainsAny(arg, shellMeta) {
			return fmt.Errorf("%w: %q", ErrArgsInvalid, arg)
		}
	}
	return nil
}

// VerifySignature checks the descriptor signature against the pinned public key.
// A malformed or foreign signature is refused, so an attacker who can write to
// the plugin directory still cannot promote their own artifact.
// VerifySignature 用固定公钥校验描述符签名。畸形或外来签名一律拒绝，因此能写插件目录
// 的攻击者依然无法提升自己的制品。
func (d Descriptor) VerifySignature(pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return ErrPublicKeyInvalid
	}
	signature, err := DecodeSignature(d.Signature)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, d.CanonicalBytes(), signature) {
		return ErrSignatureInvalid
	}
	return nil
}

// DecodeSignature accepts base64 (standard or URL, padded or not) signature
// text and returns the raw bytes.
// DecodeSignature 接受 base64（标准或 URL、带或不带填充）签名文本并返回原始字节。
func DecodeSignature(text string) ([]byte, error) {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return nil, ErrSignatureInvalid
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	} {
		if raw, err := enc.DecodeString(trimmed); err == nil {
			return raw, nil
		}
	}
	return nil, ErrSignatureInvalid
}

// VerifyArtifact recomputes the artifact digest and compares it with the digest
// the signed descriptor pinned. A byte that changed on disk is a byte that no
// longer matches the reviewed artifact, so the plugin is refused.
// VerifyArtifact 重算制品摘要并与已签名描述符固定的摘要比对。磁盘上改变的任何字节都不再
// 匹配已评审制品，因此插件被拒绝。
func (d Descriptor) VerifyArtifact(path string) error {
	expected := NormalizeDigest(d.SHA256)
	if expected == "" {
		return fmt.Errorf("%w: descriptor pins no digest", ErrDigestMismatch)
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDigestMismatch, err)
	}
	defer file.Close()
	// Hash the artifact as a stream, rather than allocating its entire size.
	sum := sha256.New()
	if _, err := io.Copy(sum, file); err != nil {
		return fmt.Errorf("%w: %v", ErrDigestMismatch, err)
	}
	if hex.EncodeToString(sum.Sum(nil)) != expected {
		return ErrDigestMismatch
	}
	return nil
}

// NormalizeDigest strips the optional "sha256:" prefix and lowercases the hex.
// NormalizeDigest 去掉可选的 "sha256:" 前缀并把十六进制转为小写。
func NormalizeDigest(digest string) string {
	trimmed := strings.ToLower(strings.TrimSpace(digest))
	return strings.TrimPrefix(trimmed, "sha256:")
}

// DigestOf returns the canonical "sha256:<hex>" digest of a byte slice, so
// registration and verification cannot disagree about the text form.
// DigestOf 返回字节切片的规范 "sha256:<hex>" 摘要，使登记与校验无法在文本形式上产生分歧。
func DigestOf(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// LoadPublicKey reads the pinned Ed25519 public key from the environment,
// accepting either a raw 32-byte key or an X.509 SPKI document, both base64.
// A missing or malformed key is an error, never a silent "verification
// disabled": without a key no plugin may run.
// LoadPublicKey 从环境读取固定的 Ed25519 公钥，接受 base64 的裸 32 字节公钥或 X.509 SPKI
// 文档。密钥缺失或畸形一律报错，绝不静默「关闭校验」：没有密钥任何插件都不得运行。
func LoadPublicKey(encoded string) (ed25519.PublicKey, error) {
	trimmed := strings.TrimSpace(encoded)
	if trimmed == "" {
		return nil, ErrPublicKeyMissing
	}
	raw, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		if raw, err = base64.RawStdEncoding.DecodeString(trimmed); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrPublicKeyInvalid, err)
		}
	}
	if len(raw) == ed25519.PublicKeySize {
		return ed25519.PublicKey(raw), nil
	}
	// X.509 SPKI: SubjectPublicKeyInfo{ AlgorithmIdentifier, BIT STRING key }.
	// The Ed25519 OID is 1.3.101.112, encoded as 06 03 2B 65 70.
	const ed25519SPKIPrefix = "302a300506032b6570032100"
	hexed := hex.EncodeToString(raw)
	if strings.HasPrefix(hexed, ed25519SPKIPrefix) && len(hexed) == len(ed25519SPKIPrefix)+2*ed25519.PublicKeySize {
		key, err := hex.DecodeString(hexed[len(ed25519SPKIPrefix):])
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrPublicKeyInvalid, err)
		}
		return ed25519.PublicKey(key), nil
	}
	return nil, fmt.Errorf("%w: expected a raw 32-byte or SPKI Ed25519 key", ErrPublicKeyInvalid)
}

// ResolveRegistered loads the descriptor for a registered plugin id from the
// registry directory and returns the descriptor together with the artifact
// path. The id is validated as a single safe path element first, so a request
// can never traverse out of the registry root.
// ResolveRegistered 从注册目录按已注册插件 id 载入描述符，并连同制品路径一起返回。
// id 先被校验为单个安全路径元素，因此请求永远无法穿越出注册根目录。
func ResolveRegistered(registryDir, id string) (Descriptor, string, error) {
	if !validID(id) {
		return Descriptor{}, "", fmt.Errorf("%w: %q", ErrDescriptorInvalid, id)
	}
	root := filepath.Clean(registryDir)
	descriptorPath := filepath.Join(root, id, "plugin.json")
	descriptor, err := LoadDescriptor(descriptorPath)
	if err != nil {
		return Descriptor{}, "", err
	}
	if descriptor.ID != id {
		return Descriptor{}, "", fmt.Errorf("%w: descriptor id %q does not match %q", ErrDescriptorInvalid, descriptor.ID, id)
	}
	artifact := filepath.Join(root, id, filepath.Base(descriptor.Entrypoint))
	return descriptor, artifact, nil
}

func validID(id string) bool {
	if id == "" || id == "." || id == ".." {
		return false
	}
	if strings.ContainsAny(id, "/\\"+shellMeta) {
		return false
	}
	for _, r := range id {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.' {
			continue
		}
		return false
	}
	return true
}

// StrictDecoder returns a decoder that rejects unknown fields and preserves
// numeric precision, so a plugin response cannot smuggle unmodelled keys or
// lose digits that a metric value depends on.
// StrictDecoder 返回拒绝未知字段并保留数值精度的解码器，使插件响应无法夹带未建模的键，
// 也不会丢失指标数值依赖的位数。
func StrictDecoder(r io.Reader) *json.Decoder {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	dec.UseNumber()
	return dec
}

// DecodeStrict decodes exactly one strict JSON document and rejects trailing
// data.
// DecodeStrict 严格解码恰好一份 JSON 文档并拒绝尾随数据。
func DecodeStrict(raw []byte, target any) error {
	dec := StrictDecoder(bytes.NewReader(raw))
	if err := dec.Decode(target); err != nil {
		return err
	}
	return ensureNoTrailingData(dec)
}

// DecodeNDJSONStrict decodes line-delimited JSON, applying the same strict rules
// to every line and reporting the offending line so a malformed stream is
// attributable instead of silently truncated.
// DecodeNDJSONStrict 解码按行分隔的 JSON，对每一行施加同样的严格规则，并报告出错行号，
// 使畸形流可归因，而不是被静默截断。
func DecodeNDJSONStrict(raw []byte, makeTarget func() any, visit func(line int, target any) error) error {
	line := 0
	for _, candidate := range bytes.Split(raw, []byte("\n")) {
		trimmed := bytes.TrimSpace(candidate)
		if len(trimmed) == 0 {
			continue
		}
		line++
		target := makeTarget()
		if err := DecodeStrict(trimmed, target); err != nil {
			return fmt.Errorf("line %d: %w", line, err)
		}
		if err := visit(line, target); err != nil {
			return fmt.Errorf("line %d: %w", line, err)
		}
	}
	if line == 0 {
		return errors.New("no NDJSON records")
	}
	return nil
}

func ensureNoTrailingData(dec *json.Decoder) error {
	if _, err := dec.Token(); err != io.EOF {
		return ErrTrailingData
	}
	return nil
}

var (
	secretAssignment = regexp.MustCompile(`(?i)(token|secret|password|passwd|api[_-]?key|authorization|bearer|credential|private[_-]?key)["']?\s*[:=]\s*["']?[^\s"',;]+`)
	opaqueToken      = regexp.MustCompile(`[A-Za-z0-9+/=_-]{32,}`)
)

// SanitizeStderr makes untrusted plugin output safe to persist: control
// characters are dropped, secret-shaped assignments and long opaque tokens are
// redacted, and the remainder is truncated. Diagnostics stay useful without
// turning the log into a credential leak or a terminal-escape vector.
// SanitizeStderr 让不可信的插件输出可以安全持久化：丢弃控制字符、遮蔽形如密钥的赋值与长
// 不透明令牌、并截断剩余部分。诊断仍然有用，而日志不会变成凭据泄漏或终端转义载体。
func SanitizeStderr(raw string, limit int) string {
	if limit <= 0 {
		limit = DefaultStderrLimit
	}
	redacted := secretAssignment.ReplaceAllString(raw, "$1=***")
	redacted = opaqueToken.ReplaceAllString(redacted, "***")
	cleaned := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, redacted)
	if len(cleaned) > limit {
		cleaned = cleaned[:limit]
	}
	return strings.TrimSpace(cleaned)
}
