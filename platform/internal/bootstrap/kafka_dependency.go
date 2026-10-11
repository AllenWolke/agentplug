package bootstrap

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/segmentio/kafka-go"
)

// KafkaDependency gates worker startup on broker metadata, including when
// Docker restarts containers without Compose's dependency ordering. It never
// creates topics, publishes messages, or owns the module's producer/consumer.
type KafkaDependency struct {
	brokers []string
}

func NewKafkaDependency(brokers []string) *KafkaDependency {
	return &KafkaDependency{brokers: append([]string(nil), brokers...)}
}

func (d *KafkaDependency) Name() string { return "kafka" }

func (d *KafkaDependency) Check(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if d != nil {
		for _, address := range d.brokers {
			if err := checkCtx.Err(); err != nil {
				return err
			}
			if strings.TrimSpace(address) == "" {
				continue
			}
			conn, err := (&kafka.Dialer{Timeout: 2 * time.Second}).DialContext(checkCtx, "tcp", address)
			if err != nil {
				continue
			}
			deadline, _ := checkCtx.Deadline()
			_ = conn.SetDeadline(deadline)
			brokers, err := conn.Brokers()
			_ = conn.Close()
			if err == nil && len(brokers) > 0 {
				return nil
			}
		}
	}
	if err := checkCtx.Err(); err != nil {
		return err
	}
	return errors.New("Kafka broker metadata unavailable")
}

func (d *KafkaDependency) Close(context.Context) error { return nil }
