package notification

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HTTPAdapter is a deliberately small ChannelAdapter for a configured
// enterprise webhook. The outbox remains the source of truth and retries are
// performed by Dispatcher, so replacing this with Kafka/WeCom/SMTP does not
// change business modules. / HTTPAdapter 是可替换的企业 Webhook 通道。
type HTTPAdapter struct {
	URL    string
	Client *http.Client
}

func NewHTTPAdapter(rawURL string) (*HTTPAdapter, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("notification webhook must be an absolute http(s) URL")
	}
	return &HTTPAdapter{URL: u.String(), Client: &http.Client{Timeout: 10 * time.Second}}, nil
}

func (a *HTTPAdapter) Send(ctx context.Context, event Event) error {
	if a == nil || a.Client == nil || strings.TrimSpace(a.URL) == "" {
		return ErrAdapterUnavailable
	}
	if err := event.ValidateForDelivery(); err != nil {
		return err
	}
	if ctx == nil {
		return errors.New("notification channel context is required")
	}
	body, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode notification event: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, a.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	// Channel providers may retry after a timeout or process restart. Exposing
	// the immutable event ID lets a real downstream provider deduplicate the
	// request; it does not pretend that an HTTP 2xx is durable delivery.
	request.Header.Set("Idempotency-Key", event.ID)
	request.Header.Set("X-Notification-Event-ID", event.ID)
	// A receiver may redirect to an unapproved destination. Preserve the
	// configured transport/timeout without forwarding event data elsewhere.
	client := *a.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
	if err != nil {
		// url.Error includes the configured URL, which may contain a secret
		// webhook query. Do not persist that value in retry or dead-letter state.
		return errors.New("notification channel request failed")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("notification channel returned status %d", response.StatusCode)
	}
	return nil
}
