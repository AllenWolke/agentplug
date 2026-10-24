package notification

import (
	"errors"
	"strings"
)

// KafkaStartOffset is an immutable deployment boundary, not a seek requested
// by a message or a consumer. Offset itself is the first eligible record.
type KafkaStartOffset struct {
	Topic     string `json:"topic"`
	Partition int    `json:"partition"`
	Offset    int64  `json:"offset"`
}

type kafkaPartition struct {
	topic     string
	partition int
}

func kafkaStartOffsetMap(values []KafkaStartOffset) (map[kafkaPartition]int64, error) {
	deny := errors.New("invalid Kafka historical offset boundary")
	if len(values) > 4096 {
		return nil, deny
	}
	result := make(map[kafkaPartition]int64, len(values))
	for _, value := range values {
		if value.Topic == "" || len(value.Topic) > 249 || value.Topic == "." || value.Topic == ".." || value.Partition < 0 || int64(value.Partition) > 1<<31-1 || value.Offset < 0 || strings.ContainsFunc(value.Topic, func(r rune) bool {
			return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-')
		}) {
			return nil, deny
		}
		key := kafkaPartition{value.Topic, value.Partition}
		if _, duplicate := result[key]; duplicate {
			return nil, deny
		}
		result[key] = value.Offset
	}
	return result, nil
}

func ValidateKafkaStartOffsets(values []KafkaStartOffset) error {
	_, err := kafkaStartOffsetMap(values)
	return err
}
