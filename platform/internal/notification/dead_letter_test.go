package notification

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/segmentio/kafka-go"
)

func TestDeadLetterSourceIdentityAndDiagnosticPrivacy(t *testing.T) {
	m := kafka.Message{Topic: "platform.notification", Partition: 2, Offset: 15, Key: []byte("PRIVATE_USER_KEY"), Value: []byte(`{"id":"e1","tenant_id":"t1","department_id":"d1","application_id":"a1","topic":"platform.notification","event_type":"test","partition_key":"p1","payload":{"body":"PRIVATE_BODY"}}`), Headers: []kafka.Header{{Key: "authorization", Value: []byte("SECRET_KEY_SENTINEL")}}}
	s, e := deadLetterSource("group1", m)
	if e != nil {
		t.Fatal(e)
	}
	other := s
	other.Group = "group2"
	if other.ID() == s.ID() {
		t.Fatal("groups share a source identity")
	}
	m2 := m
	m2.Value = []byte("changed")
	changed, e := deadLetterSource("group1", m2)
	if e != nil || changed.ID() != s.ID() || changed.Digest == s.Digest {
		t.Fatal("source tamper binding lost", e)
	}
	r, e := newDeadLetterRecord(s, m, errors.New("Authorization: SECRET_KEY_SENTINEL; request=PRIVATE_BODY"), 3)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(r.Metadata)
	headers, _ := json.Marshal(safeDeadLetterHeaders(r.Metadata))
	for _, secret := range []string{"SECRET_KEY_SENTINEL", "PRIVATE_BODY", "PRIVATE_USER_KEY"} {
		if strings.Contains(string(raw)+string(headers), secret) {
			t.Fatal("private data leaked into diagnostics")
		}
	}
	if r.Metadata.TenantID != "t1" || r.Metadata.Attempts != 3 || r.Metadata.ErrorCode != "DELIVERY_FAILED" {
		t.Fatal("invalid safe metadata")
	}
	m.Value = []byte(`{"bad":"record"}`)
	m.Headers = append(m.Headers, kafka.Header{Key: "tenant_id", Value: []byte("spoofed")})
	s, _ = deadLetterSource("group1", m)
	r, e = newDeadLetterRecord(s, m, ErrInvalidEvent, 1)
	if e != nil || r.Metadata.TenantID != "" || r.Metadata.EventID != "" || r.Metadata.ErrorCode != "INVALID_EVENT" {
		t.Fatal("headers forged tenant ownership", e)
	}
}

type failingDeadLetterSink struct {
	publishedError, ackError error
	quarantined              int
	attempts                 int
}

func (s *failingDeadLetterSink) StartAttempt(context.Context, DeadLetterSource, int) (DeadLetterAttempt, error) {
	s.attempts++
	return DeadLetterAttempt{Attempts: s.attempts}, nil
}
func (s *failingDeadLetterSink) Quarantine(context.Context, DeadLetterRecord) error {
	s.quarantined++
	return nil
}
func (s *failingDeadLetterSink) MarkPublished(context.Context, DeadLetterSource) error {
	return s.publishedError
}
func (s *failingDeadLetterSink) MarkAcknowledged(context.Context, DeadLetterSource) error {
	return s.ackError
}
func TestDeadLetterReceiptFailureCannotCommitSource(t *testing.T) {
	for _, mode := range []string{"dlq", "ack"} {
		t.Run(mode, func(t *testing.T) {
			r := &kafkaReaderFake{messages: []kafka.Message{{Topic: "events", Offset: 8, Value: []byte("{}")}}}
			w := &kafkaWriterFake{}
			injected := errors.New("injected durable receipt failure")
			sink := &failingDeadLetterSink{}
			if mode == "dlq" {
				sink.publishedError = injected
			} else {
				sink.ackError = injected
			}
			bus := &KafkaGoEventBus{reader: r, writer: w, group: "tests", dlqTopic: "dead", max: 1, backoff: time.Nanosecond, deadLetters: sink}
			e := bus.ConsumeMessages(context.Background(), func(context.Context, EventMessage) DeliveryResult {
				if mode == "ack" {
					return Ack()
				}
				return DeadLetter(ErrInvalidEvent)
			})
			if !errors.Is(e, injected) || len(r.commits) != 0 {
				t.Fatal("source committed without durable receipt", e)
			}
			if mode == "dlq" && (sink.quarantined != 1 || len(w.messages) != 1) {
				t.Fatal("dead-letter intent not recorded before submission")
			}
		})
	}
}

func TestDeadLetterFailureCodesNeverUseErrorStrings(t *testing.T) {
	for _, err := range []error{nil, errors.New("sk-private"), context.Canceled, context.DeadlineExceeded, ErrInvalidEvent, ErrAdapterUnavailable, ErrClaimLost} {
		code := truncateKafkaError(err)
		if code == "" || strings.Contains(code, "sk-private") {
			t.Fatal("unsafe failure code")
		}
	}
}
