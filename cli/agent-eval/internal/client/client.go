// Package client uses only the platform's public authenticated gateway.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	agenteval "github.com/lexagent/agent-evaluation"
)

type Error struct {
	Status int
	Code   string
}

func (e *Error) Error() string { return fmt.Sprintf("platform HTTP %d (%s)", e.Status, e.Code) }

type Client struct {
	base       *url.URL
	http       *http.Client
	refresh    sync.Mutex
	generation uint64
}
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type Workspace struct {
	TenantID      string `json:"tenant_id"`
	DepartmentID  string `json:"department_id"`
	ApplicationID string `json:"application_id"`
}
type Resource struct {
	ID       string          `json:"id"`
	Status   string          `json:"status"`
	Revision uint64          `json:"revision"`
	Data     json.RawMessage `json:"data"`
}

func New(base string) (*Client, error) {
	u, e := url.Parse(base)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, errors.New("platform URL must be an http(s) origin without credentials or paths")
	}
	jar, _ := cookiejar.New(nil)
	return &Client{base: u, http: &http.Client{Timeout: 25 * time.Second, Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (c *Client) Do(ctx context.Context, method, path string, input, output any) error {
	return c.do(ctx, method, path, input, output, true)
}
func (c *Client) do(ctx context.Context, method, path string, input, output any, refresh bool) error {
	var generation uint64
	if refresh {
		c.refresh.Lock()
		generation = c.generation
		c.refresh.Unlock()
	}
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
		return errors.New("invalid public API path")
	}
	endpoint := *c.base
	parts, e := url.Parse(path)
	if e != nil {
		return errors.New("invalid public API path")
	}
	endpoint.Path, endpoint.RawQuery = parts.Path, parts.RawQuery
	var data []byte
	if input != nil {
		data, e = json.Marshal(input)
		if e != nil {
			return e
		}
	}
	r, e := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(data))
	if e != nil {
		return e
	}
	r.Header.Set("Origin", strings.TrimRight(c.base.String(), "/"))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	response, e := c.http.Do(r)
	if e != nil {
		return errors.New("platform connection failed; no unconfirmed command is replayed")
	}
	defer response.Body.Close()
	if response.StatusCode == 401 && refresh && !strings.HasPrefix(path, "/auth/") {
		c.refresh.Lock()
		if generation == c.generation {
			e = c.do(ctx, http.MethodPost, "/auth/refresh", map[string]any{}, nil, false)
			if e == nil {
				c.generation++
			}
		}
		c.refresh.Unlock()
		if e != nil {
			return e
		}
		return c.do(ctx, method, path, input, output, false)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var body struct {
			Error json.RawMessage `json:"error"`
			Code  string          `json:"code"`
		}
		_ = json.NewDecoder(io.LimitReader(response.Body, 8192)).Decode(&body)
		var code string
		if len(body.Error) > 0 {
			var object struct {
				Code string `json:"code"`
			}
			if json.Unmarshal(body.Error, &code) != nil && json.Unmarshal(body.Error, &object) == nil {
				code = object.Code
			}
		}
		if code == "" {
			code = body.Code
		}
		if !regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`).MatchString(code) {
			code = "REQUEST_REJECTED"
		}
		if code == "" {
			code = "REQUEST_REJECTED"
		}
		return &Error{response.StatusCode, code}
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, (4<<20)+1))
	if readErr != nil || len(body) > 4<<20 {
		return errors.New("invalid or oversized platform JSON response")
	}
	var envelope struct {
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal(body, &envelope) == nil && len(envelope.Error) > 0 && string(envelope.Error) != "null" {
		var code string
		var object struct {
			Code string `json:"code"`
		}
		if json.Unmarshal(envelope.Error, &code) != nil && json.Unmarshal(envelope.Error, &object) == nil {
			code = object.Code
		}
		if !regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`).MatchString(code) {
			code = "REQUEST_REJECTED"
		}
		return &Error{response.StatusCode, code}
	}
	if output == nil {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if e = decoder.Decode(output); e != nil {
		return errors.New("invalid or oversized platform JSON response")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("platform response contains trailing data")
	}
	return nil
}
func (c *Client) Login(ctx context.Context, credentials Credentials) error {
	return c.do(ctx, "POST", "/auth/login", credentials, nil, false)
}
func (c *Client) Logout(ctx context.Context) {
	_ = c.do(ctx, "POST", "/auth/logout", map[string]any{}, nil, false)
}
func (c *Client) Workspaces(ctx context.Context) ([]Workspace, error) {
	var out struct {
		Items []Workspace `json:"application_workspaces"`
	}
	e := c.Do(ctx, "GET", "/api/modules/identity/me/workspaces", nil, &out)
	return out.Items, e
}
func (c *Client) Switch(ctx context.Context, w Workspace) error {
	return c.Do(ctx, "POST", "/auth/workspace", w, nil)
}
func (c *Client) Discover(ctx context.Context) (agenteval.Discovery, error) {
	out := agenteval.Discovery{Items: []agenteval.Agent{}}
	seen := map[string]bool{}
	for page := 1; page <= 1000; page++ {
		var p agenteval.Discovery
		e := c.Do(ctx, "GET", fmt.Sprintf("/api/modules/evaluation-product/agents?page=%d&page_size=100", page), nil, &p)
		if e != nil {
			return out, e
		}
		if p.Page != page || p.PageSize != 100 || p.Total < 0 || len(p.Items) > 100 {
			return out, errors.New("invalid discovery pagination")
		}
		if page == 1 {
			out = p
			out.Items = []agenteval.Agent{}
		} else if out.Total != p.Total || out.OnlineAgents != p.OnlineAgents || out.OnlineInstances != p.OnlineInstances || out.Evaluable != p.Evaluable {
			return out, errors.New("discovery changed while paging; rediscover before selecting")
		}
		for _, item := range p.Items {
			if item.InstallationID == "" || seen[item.InstallationID] {
				return out, errors.New("discovery contains duplicate or missing installation identifiers")
			}
			seen[item.InstallationID] = true
		}
		out.Items = append(out.Items, p.Items...)
		if len(out.Items) > p.Total {
			return out, errors.New("discovery total is inconsistent")
		}
		if len(out.Items) >= p.Total {
			return out, nil
		}
		if len(p.Items) == 0 {
			return out, errors.New("discovery changed or returned an incomplete page")
		}
	}
	return out, errors.New("discovery limit exceeded")
}
func (c *Client) Trajectory(ctx context.Context, id string) (agenteval.Trajectory, error) {
	var t agenteval.Trajectory
	e := c.Do(ctx, "GET", "/api/modules/evaluation-product/trajectories/"+url.PathEscape(id), nil, &t)
	if e == nil && (t.Version != agenteval.TrajectoryVersion || t.RunID != id || t.Source != "platform") {
		e = errors.New("unverified trajectory response")
	}
	return t, e
}
func (c *Client) GetResource(ctx context.Context, kind, id string) (Resource, error) {
	var r Resource
	e := c.Do(ctx, "GET", "/api/modules/evaluation-product/"+kind+"/"+url.PathEscape(id), nil, &r)
	if e == nil && (r.ID != id || r.Status == "" || r.Revision == 0) {
		e = errors.New("invalid platform resource acknowledgement")
	}
	return r, e
}
