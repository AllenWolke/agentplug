package agentgateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/telemetry"
	"go.opentelemetry.io/otel/trace"
)

const (
	defaultHTTPBodyLimit  int64 = 8 << 20
	defaultHTTPEventLimit       = 1 << 20
)

var (
	ErrHTTPInvalidResponse = errors.New("agent HTTP transport returned an invalid response")
	ErrHTTPEventProtocol   = errors.New("agent HTTP transport returned an invalid event stream")
)

// HTTPTransport is the platform-owned JSON/SSE implementation of the
// language-neutral Agent Execution v2 transport. The same RemoteAdapter can
// therefore target Python, Go or Java Agents without importing their SDKs.
// HTTPTransport 是平台所有的 JSON/SSE 实现；RemoteAdapter 可以调用 Python、Go
// 或 Java Agent，而不需要把任何语言 SDK 编译进平台进程。
type HTTPTransport struct {
	Client     *http.Client
	BodyLimit  int64
	EventLimit int
}

func NewHTTPTransport(client *http.Client) HTTPTransport {
	if client == nil {
		client = &http.Client{}
	}
	return HTTPTransport{Client: client, BodyLimit: defaultHTTPBodyLimit, EventLimit: defaultHTTPEventLimit}
}

func (t HTTPTransport) Invoke(ctx context.Context, target Target, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	return t.execute(ctx, target, "/internal/agent-execution/v2/invoke", request)
}

func (t HTTPTransport) Run(ctx context.Context, target Target, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	return t.execute(ctx, target, "/internal/agent-execution/v2/runs", request)
}

func (t HTTPTransport) Resume(ctx context.Context, target Target, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	return t.execute(ctx, target, "/internal/agent-execution/v2/runs/"+url.PathEscape(request.Scope.RunID)+"/resume", request)
}

func (t HTTPTransport) Cancel(ctx context.Context, target Target, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	return t.execute(ctx, target, "/internal/agent-execution/v2/runs/"+url.PathEscape(request.Scope.RunID)+"/cancel", request)
}

func (t HTTPTransport) execute(ctx context.Context, target Target, path string, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	var response contract.ExecuteResponse
	if err := t.request(ctx, http.MethodPost, target, path, request, &response); err != nil {
		return contract.ExecuteResponse{}, err
	}
	if response.ProtocolVersion != contract.ProtocolVersion || response.RunID == "" || response.Status == "" || (response.Handoff != nil && response.Status != "waiting") {
		return contract.ExecuteResponse{}, ErrHTTPInvalidResponse
	}
	return response, nil
}

func (t HTTPTransport) request(ctx context.Context, method string, target Target, path string, input any, output any) (returnedErr error) {
	ctx, span := telemetry.Start(ctx, "platform.agent.http", trace.SpanKindClient)
	defer span.End()
	defer func() {
		if returnedErr != nil {
			telemetry.Failed(span, "AGENT_TRANSPORT_FAILED")
		}
	}()
	if target.Transport != "http" && target.Transport != "https" {
		return ErrInvalidTarget
	}
	if err := target.Validate(); err != nil {
		return err
	}
	base, err := url.Parse(strings.TrimRight(target.Endpoint, "/"))
	if err != nil || base.Host == "" {
		return ErrInvalidTarget
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(base.String(), "/")+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	telemetry.Inject(ctx, req.Header)
	if execute, ok := input.(contract.ExecuteRequest); ok {
		req.Header.Set("Authorization", "Bearer "+execute.ContextToken)
	}
	client := t.Client
	if client == nil {
		client = http.DefaultClient
	}
	// A signed command and its exit receipt belong to this registered endpoint.
	// In particular, 307/308 must not replay a body containing a context token
	// to a different endpoint. Clone to preserve caller timeouts/transports.
	executionClient := *client
	executionClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	response, err := executionClient.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, t.bodyLimit()))
	if err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var appErr contract.AppError
		if json.Unmarshal(body, &appErr) == nil && appErr.Code != "" {
			return appErr
		}
		// SDK business failures use the versioned ExecuteResponse envelope.
		// Bind that terminal failure to this exact command before treating it
		// as completed; malformed or foreign-run replies remain uncertain.
		var failed contract.ExecuteResponse
		execute, isExecute := input.(contract.ExecuteRequest)
		if isExecute && json.Unmarshal(body, &failed) == nil && failed.ProtocolVersion == contract.ProtocolVersion && failed.RunID == execute.Scope.RunID && failed.Status == "failed" {
			completed, err := NewCompletedExecutionFailure(failed)
			if err == nil {
				return completed
			}
			return ErrHTTPInvalidResponse
		}
		return fmt.Errorf("%w: status=%d", ErrHTTPInvalidResponse, response.StatusCode)
	}
	if !json.Valid(body) || json.Unmarshal(body, output) != nil {
		return ErrHTTPInvalidResponse
	}
	return nil
}

func (t HTTPTransport) Events(ctx context.Context, target Target, request contract.EventRequest) (EventStream, error) {
	if target.Transport != "http" && target.Transport != "https" {
		return EventStream{}, ErrInvalidTarget
	}
	if err := target.Validate(); err != nil {
		return EventStream{}, err
	}
	if err := request.Validate(); err != nil {
		return EventStream{}, err
	}
	base := strings.TrimRight(target.Endpoint, "/")
	endpoint := base + "/internal/agent-execution/v2/runs/" + url.PathEscape(request.Scope.RunID) + "/events"
	raw, err := json.Marshal(request)
	if err != nil {
		return EventStream{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return EventStream{}, err
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+request.ContextToken)
	client := t.Client
	if client == nil {
		client = http.DefaultClient
	}
	eventClient := *client
	eventClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	response, err := eventClient.Do(req)
	if err != nil {
		return EventStream{}, err
	}
	if response.StatusCode != http.StatusOK || !strings.HasPrefix(strings.ToLower(response.Header.Get("Content-Type")), "text/event-stream") {
		_ = response.Body.Close()
		return EventStream{}, fmt.Errorf("%w: event status=%d", ErrHTTPInvalidResponse, response.StatusCode)
	}
	events := make(chan contract.ExecutionEvent)
	errorsCh := make(chan error, 1)
	go parseHTTPEventStream(ctx, response.Body, request.Scope.RunID, t.eventLimit(), events, errorsCh)
	return EventStream{Events: events, Errors: errorsCh, Close: response.Body.Close}, nil
}

func (t HTTPTransport) bodyLimit() int64 {
	if t.BodyLimit > 0 {
		return t.BodyLimit
	}
	return defaultHTTPBodyLimit
}

func (t HTTPTransport) eventLimit() int {
	if t.EventLimit > 0 {
		return t.EventLimit
	}
	return defaultHTTPEventLimit
}

func parseHTTPEventStream(ctx context.Context, body io.ReadCloser, runID string, limit int, events chan<- contract.ExecutionEvent, errorsCh chan<- error) {
	defer close(events)
	defer close(errorsCh)
	defer body.Close()
	scanner := bufio.NewScanner(body)
	initial := 64 << 10
	if limit < initial {
		initial = limit
	}
	scanner.Buffer(make([]byte, initial), limit)
	var id, eventType string
	data := make([]string, 0, 1)
	frameBytes := 0
	dispatch := func() error {
		if id == "" && eventType == "" && len(data) == 0 {
			return nil
		}
		seq, err := strconv.ParseUint(id, 10, 64)
		if err != nil || seq == 0 || seq > contract.MaxAgentEventSequence || eventType == "" || len(data) == 0 {
			return ErrHTTPEventProtocol
		}
		var event contract.ExecutionEvent
		raw := []byte(strings.Join(data, "\n"))
		if !json.Valid(raw) || json.Unmarshal(raw, &event) != nil || event.RunID != runID || event.Seq != seq || event.EventType != eventType {
			return ErrHTTPEventProtocol
		}
		select {
		case events <- event:
			id, eventType, data = "", "", data[:0]
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	for scanner.Scan() {
		lineBytes := len(scanner.Bytes()) + 1 // Include the LF delimiter in the frame budget.
		if lineBytes > limit-frameBytes {
			errorsCh <- ErrHTTPEventProtocol
			return
		}
		frameBytes += lineBytes
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if line == "" {
			if err := dispatch(); err != nil {
				errorsCh <- err
				return
			}
			frameBytes = 0
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		field, value, ok := strings.Cut(line, ":")
		if !ok {
			errorsCh <- ErrHTTPEventProtocol
			return
		}
		value = strings.TrimPrefix(value, " ")
		switch field {
		case "id":
			if id != "" {
				errorsCh <- ErrHTTPEventProtocol
				return
			}
			id = value
		case "event":
			if eventType != "" {
				errorsCh <- ErrHTTPEventProtocol
				return
			}
			eventType = value
		case "data":
			data = append(data, value)
		default:
			errorsCh <- ErrHTTPEventProtocol
			return
		}
	}
	if err := scanner.Err(); err != nil {
		errorsCh <- fmt.Errorf("%w: %v", ErrHTTPEventProtocol, err)
		return
	}
	if id != "" || eventType != "" || len(data) != 0 {
		errorsCh <- fmt.Errorf("%w: truncated event", ErrHTTPEventProtocol)
	}
}

var _ Transport = HTTPTransport{}
