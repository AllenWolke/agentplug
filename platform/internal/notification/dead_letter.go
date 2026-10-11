package notification

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/segmentio/kafka-go"
)

const DeadLetterVersion = "kafka-dead-letter/v1"
const MaximumDeadLetterBytes = 10 << 20

var ErrDeadLetterConflict = errors.New("dead-letter binding conflict")
var ErrDeadLetterUnavailable = errors.New("dead-letter authority unavailable")
var ErrDeadLetterForbidden = errors.New("dead-letter access denied")

// The source position is namespaced by consumer group. Body/key/header hashes
// prevent a repaired or malicious record from reusing the same source identity.
type DeadLetterSource struct {
	Group     string `json:"consumer_group"`
	Topic     string `json:"source_topic"`
	Partition int    `json:"source_partition"`
	Offset    int64  `json:"source_offset"`
	Digest    string `json:"source_digest"`
}

func (s DeadLetterSource) ID() string {
	raw, _ := json.Marshal(struct {
		Group, Topic string
		Partition    int
		Offset       int64
	}{s.Group, s.Topic, s.Partition, s.Offset})
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}
func (s DeadLetterSource) Validate() error {
	if !deadLetterToken(s.Group, 255) || !deadLetterToken(s.Topic, 255) || s.Partition < 0 || s.Offset < 0 || !deadLetterDigest(s.Digest) {
		return ErrDeadLetterConflict
	}
	return nil
}
func deadLetterToken(s string, max int) bool {
	if s == "" || len(s) > max {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._:-", c)) {
			return false
		}
	}
	return true
}
func deadLetterDigest(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && s == strings.ToLower(s)
}
func deadLetterSource(group string, m kafka.Message) (DeadLetterSource, error) {
	if len(m.Value) > MaximumDeadLetterBytes || len(m.Key) > 65536 || len(m.Headers) > 128 {
		return DeadLetterSource{}, ErrDeadLetterConflict
	}
	// Kafka header order is preserved in the digest; the exact original record
	// must be replayed. Duplicate headers are not a source of tenant authority.
	headerBytes := 0
	for _, h := range m.Headers {
		headerBytes += len(h.Key) + len(h.Value)
	}
	if headerBytes > 65536 {
		return DeadLetterSource{}, ErrDeadLetterConflict
	}
	raw, e := json.Marshal(struct {
		Key, Value []byte
		Headers    []kafka.Header
	}{nonNilBytes(m.Key), nonNilBytes(m.Value), append([]kafka.Header{}, m.Headers...)})
	if e != nil {
		return DeadLetterSource{}, e
	}
	h := sha256.Sum256(raw)
	s := DeadLetterSource{group, m.Topic, m.Partition, m.Offset, hex.EncodeToString(h[:])}
	return s, s.Validate()
}

// Public metadata never contains the body, key, headers or error text. Scope
// comes from a valid event body, and is only a filter; IAM still authorizes it.
type DeadLetterMetadata struct {
	Version       string           `json:"version"`
	ID            string           `json:"id"`
	Source        DeadLetterSource `json:"source"`
	Attempts      int              `json:"attempts"`
	ErrorCode     string           `json:"error_code"`
	PayloadBytes  int              `json:"payload_bytes"`
	PayloadDigest string           `json:"payload_digest"`
	EventID       string           `json:"event_id,omitempty"`
	TenantID      string           `json:"tenant_id,omitempty"`
	DepartmentID  string           `json:"department_id,omitempty"`
	ApplicationID string           `json:"application_id,omitempty"`
	Status        string           `json:"status"`
	Revision      int64            `json:"revision"`
	CreatedAt     time.Time        `json:"created_at"`
}

// Raw is private to the broker boundary and SQL owner. It is not an HTTP/CLI
// response. Retaining raw data requires the DLQ topic/SQL runtime ACLs.
type DeadLetterRecord struct {
	Metadata DeadLetterMetadata
	Raw      kafka.Message
}

func newDeadLetterRecord(source DeadLetterSource, m kafka.Message, cause error, attempts int) (DeadLetterRecord, error) {
	if source.Validate() != nil || attempts < 1 || attempts > 1000000 {
		return DeadLetterRecord{}, ErrDeadLetterConflict
	}
	h := sha256.Sum256(m.Value)
	meta := DeadLetterMetadata{Version: DeadLetterVersion, ID: source.ID(), Source: source, Attempts: attempts, ErrorCode: kafkaFailureCode(cause), PayloadBytes: len(m.Value), PayloadDigest: hex.EncodeToString(h[:]), Status: "quarantined", Revision: 1, CreatedAt: time.Now().UTC()}
	if event, e := decodeKafkaEvent(m.Value); e == nil && event.ValidateForDelivery() == nil && event.Topic == m.Topic {
		// Reject oversized/untrusted identifiers, not just JSON syntax.
		if deadLetterToken(event.ID, 255) && deadLetterToken(event.TenantID, 255) && deadLetterToken(event.DepartmentID, 255) && deadLetterToken(event.ApplicationID, 255) {
			meta.EventID, meta.TenantID, meta.DepartmentID, meta.ApplicationID = event.ID, event.TenantID, event.DepartmentID, event.ApplicationID
		}
	}
	return DeadLetterRecord{meta, m}, nil
}

func kafkaFailureCode(err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return "CANCELLED"
	case errors.Is(err, context.DeadlineExceeded):
		return "TIMEOUT"
	case errors.Is(err, ErrInvalidEvent):
		return "INVALID_EVENT"
	case errors.Is(err, ErrEventDeliveryDeadLetter):
		return "DELIVERY_EXHAUSTED"
	case errors.Is(err, ErrDeliveryInProgress):
		return "DELIVERY_IN_PROGRESS"
	case errors.Is(err, ErrAdapterUnavailable):
		return "ADAPTER_UNAVAILABLE"
	case errors.Is(err, ErrClaimLost):
		return "CLAIM_LOST"
	default:
		return "DELIVERY_FAILED"
	}
}

// The sink counts attempts before the handler, across restarts. A quarantined
// message retries only DLQ publication; an acknowledged message only commits.
// No unknown channel result or raw message is interpreted as successful work.
type DeadLetterAttempt struct {
	Attempts                           int
	Exhausted, Acknowledged, Published bool
}
type DeadLetterSink interface {
	StartAttempt(context.Context, DeadLetterSource, int) (DeadLetterAttempt, error)
	Quarantine(context.Context, DeadLetterRecord) error
	MarkPublished(context.Context, DeadLetterSource) error
	MarkAcknowledged(context.Context, DeadLetterSource) error
}

func safeDeadLetterHeaders(meta DeadLetterMetadata) []kafka.Header {
	values := map[string]string{"dlq_contract": meta.Version, "dlq_id": meta.ID, "consumer_group": meta.Source.Group, "source_topic": meta.Source.Topic, "source_partition": strconv.FormatInt(int64(meta.Source.Partition), 10), "source_offset": strconv.FormatInt(meta.Source.Offset, 10), "delivery_attempt": strconv.Itoa(meta.Attempts), "failure_reason": meta.ErrorCode, "payload_sha256": meta.PayloadDigest}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	headers := make([]kafka.Header, 0, len(keys))
	for _, k := range keys {
		headers = append(headers, kafka.Header{Key: k, Value: []byte(values[k])})
	}
	return headers
}
