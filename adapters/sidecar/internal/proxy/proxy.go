package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	agentplatform "github.com/lexagent/agent-platform-sdk-go/agentplatform"
)

var (
	ErrUnsupported      = errors.New("sidecar capability is not supported")
	ErrTLSConfigInvalid = errors.New("sidecar mutual TLS configuration is invalid")
	ErrEventStream      = errors.New("sidecar event stream is invalid")
)

// TLSFiles are the mounted workload identity and trust anchors of the sidecar.
// A client certificate is mandatory: the sidecar always presents its own
// identity to the registered upstream, which is what distinguishes it from a
// plain one-way HTTPS call. / TLSFiles 是 Sidecar 挂载的工作负载身份与信任锚。
// 客户端证书是必填项：Sidecar 始终向已登记上游出示自身身份，这正是它与普通单向
// HTTPS 调用的区别。
type TLSFiles struct {
	ClientCertFile string
	ClientKeyFile  string
	ServerCAFile   string
}

// NewMutualTLSClient builds the client the sidecar uses for its registered
// upstream. Mutual TLS is mandatory and server verification is never disabled,
// so a misconfigured deployment fails closed instead of silently downgrading to
// unauthenticated TLS. / NewMutualTLSClient 构建 Sidecar 访问已登记上游所用的
// 客户端。双向 TLS 是强制的，服务端校验永不被关闭，因此配置错误的部署会失败闭合，
// 而不会静默降级成未认证的 TLS。
func NewMutualTLSClient(files TLSFiles, timeout time.Duration) (*http.Client, error) {
	certFile, keyFile := strings.TrimSpace(files.ClientCertFile), strings.TrimSpace(files.ClientKeyFile)
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("%w: a client certificate and key are required for mutual TLS", ErrTLSConfigInvalid)
	}
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTLSConfigInvalid, err)
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{certificate},
	}
	if caFile := strings.TrimSpace(files.ServerCAFile); caFile != "" {
		raw, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrTLSConfigInvalid, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(raw) {
			return nil, fmt.Errorf("%w: the server CA file contains no certificates", ErrTLSConfigInvalid)
		}
		config.RootCAs = pool
	}
	return &http.Client{
		Timeout:       timeout,
		Transport:     &http.Transport{TLSClientConfig: config},
		CheckRedirect: NoRedirect,
	}, nil
}

// NoRedirect refuses to follow an upstream 3xx so a compromised upstream cannot
// move platform-verified egress to a host that never passed address policy.
// NoRedirect 拒绝跟随上游 3xx，避免被攻陷的上游把平台已校验的出站流量挪到从未通过
// 地址策略的主机。
func NoRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

type Proxy struct {
	BaseURL string
	Client  *http.Client
}

func (p Proxy) Invoke(ctx context.Context, request agentplatform.ExecuteRequest) (agentplatform.ExecuteResponse, error) {
	if p.BaseURL == "" || !strings.HasPrefix(p.BaseURL, "https://") {
		return agentplatform.ExecuteResponse{}, ErrUnsupported
	}
	client := p.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return agentplatform.ExecuteResponse{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(p.BaseURL, "/")+"/internal/agent-execution/v2/invoke", strings.NewReader(string(raw)))
	if err != nil {
		return agentplatform.ExecuteResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	// Forward only the signed capability, never caller-controlled identity
	// headers. / 仅转发已签名能力令牌，不转发调用方可伪造的身份头。
	if request.ContextToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+request.ContextToken)
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return agentplatform.ExecuteResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return agentplatform.ExecuteResponse{}, errors.New("sidecar returned non-success")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return agentplatform.ExecuteResponse{}, err
	}
	var output agentplatform.ExecuteResponse
	if err := json.Unmarshal(body, &output); err != nil {
		return agentplatform.ExecuteResponse{}, err
	}
	return output, nil
}

// StreamEvents relays the registered upstream's execution-event stream. It
// verifies nothing itself — the caller has already checked the signed events
// capability — but it applies the same one-way egress policy: only the signed
// capability crosses, never caller identity, and frames are flushed as they
// arrive so a live stream is never turned into one delayed response.
// StreamEvents 转发已登记上游的执行事件流。它自身不做校验（调用方已校验签名的事件
// 能力），但沿用同一出站策略：只跨出已签名能力、绝不转发调用方身份，并逐帧 flush，
// 使实时流不会退化成一次延迟响应。
func (p Proxy) StreamEvents(ctx context.Context, request agentplatform.EventRequest, eventsPath string, w http.ResponseWriter, maxBody int64) error {
	if p.BaseURL == "" || !strings.HasPrefix(p.BaseURL, "https://") {
		return ErrUnsupported
	}
	if strings.TrimSpace(eventsPath) == "" || !strings.HasPrefix(eventsPath, "/") || strings.Contains(eventsPath, "..") {
		return ErrEventStream
	}
	client := p.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	upstream, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(p.BaseURL, "/")+eventsPath, nil)
	if err != nil {
		return err
	}
	upstream.Header.Set("Accept", "text/event-stream")
	if request.ContextToken != "" {
		upstream.Header.Set("Authorization", "Bearer "+request.ContextToken)
	}
	// An event subscription is a read, not a command: it carries the standard
	// SSE resume handshake and no idempotency key. / 事件订阅是读取而非命令：携带标准
	// SSE 恢复握手，且不带幂等键。
	if request.AfterSeq > 0 {
		upstream.Header.Set("Last-Event-ID", strconv.FormatUint(request.AfterSeq, 10))
	}
	response, err := client.Do(upstream)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrEventStream, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.HasPrefix(response.Header.Get("Content-Type"), "text/event-stream") {
		return ErrEventStream
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	controller := http.NewResponseController(w)
	buffer := make([]byte, 8<<10)
	total := int64(0)
	for {
		read, readErr := response.Body.Read(buffer)
		if read > 0 {
			total += int64(read)
			if maxBody > 0 && total > maxBody {
				return nil
			}
			if _, writeErr := w.Write(buffer[:read]); writeErr != nil {
				return nil
			}
			_ = controller.Flush()
		}
		if readErr != nil {
			return nil
		}
	}
}
