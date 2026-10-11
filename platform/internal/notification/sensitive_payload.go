package notification

// Sensitive payload encryption keeps one-time verification material out of
// SQL Outbox rows and Kafka messages. / 敏感载荷加密，避免一次性验证码明文
// 进入 SQL Outbox 行或 Kafka 消息。

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const EnrollmentVerificationEventType = "identity.enrollment.contact-verification.v1"

// SealSensitivePayload encrypts bytes with AES-256-GCM and returns a versioned
// URL-safe envelope. / SealSensitivePayload 使用 AES-256-GCM 加密并返回带版本号
// 的 URL-safe 密文封套。
func SealSensitivePayload(key, plaintext []byte) (string, error) {
	if len(key) != 32 {
		return "", errors.New("sensitive payload key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create sensitive payload cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create sensitive payload AEAD: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("create sensitive payload nonce: %w", err)
	}
	sealed := aead.Seal(nil, nonce, plaintext, []byte(EnrollmentVerificationEventType))
	return "v1." + base64.RawURLEncoding.EncodeToString(append(nonce, sealed...)), nil
}

// OpenSensitivePayload authenticates and decrypts a versioned envelope.
// OpenSensitivePayload 校验并解密带版本号的密文封套。
func OpenSensitivePayload(key []byte, envelope string) ([]byte, error) {
	if len(key) != 32 || !strings.HasPrefix(envelope, "v1.") {
		return nil, errors.New("invalid sensitive payload envelope")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(envelope, "v1."))
	if err != nil {
		return nil, errors.New("invalid sensitive payload envelope")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create sensitive payload cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create sensitive payload AEAD: %w", err)
	}
	if len(raw) < aead.NonceSize()+aead.Overhead() {
		return nil, errors.New("invalid sensitive payload envelope")
	}
	nonce, ciphertext := raw[:aead.NonceSize()], raw[aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, ciphertext, []byte(EnrollmentVerificationEventType))
	if err != nil {
		return nil, errors.New("sensitive payload authentication failed")
	}
	return plaintext, nil
}

// SensitivePayloadAdapter decrypts only the enrollment-verification event
// immediately before the configured channel receives it. Other events pass
// through unchanged. / SensitivePayloadAdapter 仅在交付通道前解密注册验证码，
// 其他事件原样转发。
type SensitivePayloadAdapter struct {
	Inner ChannelAdapter
	Key   []byte
}

func (a SensitivePayloadAdapter) Send(ctx context.Context, event Event) error {
	if a.Inner == nil {
		return ErrAdapterUnavailable
	}
	if event.EventType != EnrollmentVerificationEventType {
		return a.Inner.Send(ctx, event)
	}
	sealed, ok := event.Payload["sealed_delivery"].(string)
	if !ok || sealed == "" {
		return errors.New("encrypted enrollment delivery payload is missing")
	}
	plaintext, err := OpenSensitivePayload(a.Key, sealed)
	if err != nil {
		return err
	}
	var delivery map[string]any
	if err := json.Unmarshal(plaintext, &delivery); err != nil {
		return errors.New("encrypted enrollment delivery payload is invalid")
	}
	event.Payload = delivery
	return a.Inner.Send(ctx, event)
}
