package capability

import (
	"errors"
	"strings"

	"github.com/lexagent/platform/internal/sharedkernel"
)

const (
	sendNotificationToolName = "send_notification"
	notifySelfToolName       = "notify.self"
)

func isNotificationTool(name string) bool {
	return name == sendNotificationToolName || name == notifySelfToolName
}

func notificationTextField(payload map[string]any, key string, maxBytes int) (string, error) {
	value, ok := payload[key].(string)
	value = strings.TrimSpace(value)
	if !ok || value == "" || len(value) > maxBytes || strings.ContainsRune(value, '\x00') {
		return "", errors.New("invalid notification field")
	}
	return value, nil
}

func notificationTextFieldPreserved(payload map[string]any, key string, maxBytes int) (string, error) {
	value, ok := payload[key].(string)
	if !ok || strings.TrimSpace(value) == "" || len(value) > maxBytes || strings.ContainsRune(value, '\x00') {
		return "", errors.New("invalid notification field")
	}
	return value, nil
}

// selfNotificationFields derives the recipient only from the authenticated
// human scope. Its closed payload deliberately cannot express a recipient.
func selfNotificationFields(scope sharedkernel.Scope, payload map[string]any) (title, text string, err error) {
	if scope.PrincipalType != "user" || scope.PrincipalID == "" || strings.TrimSpace(scope.PrincipalID) != scope.PrincipalID {
		return "", "", errors.New("human principal required")
	}
	if len(payload) != 2 {
		return "", "", errors.New("notification payload must contain only title and text")
	}
	if _, ok := payload["title"]; !ok {
		return "", "", errors.New("notification title required")
	}
	if _, ok := payload["text"]; !ok {
		return "", "", errors.New("notification text required")
	}
	if title, err = notificationTextFieldPreserved(payload, "title", 256); err != nil {
		return "", "", err
	}
	if text, err = notificationTextFieldPreserved(payload, "text", 4096); err != nil {
		return "", "", err
	}
	return title, text, nil
}
