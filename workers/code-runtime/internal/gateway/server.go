package gateway

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	protocol "github.com/lexagent/code-runtime-contract"
	"github.com/lexagent/code-runtime/internal/sandbox"
)

type Profile struct {
	ID       string          `json:"id"`
	ToolName string          `json:"tool_name"`
	Language string          `json:"language"`
	Limits   protocol.Limits `json:"limits"`
}
type Executor interface {
	Run(context.Context, sandbox.Request) (sandbox.Result, error)
}
type Server struct {
	controller string
	public     ed25519.PublicKey
	profiles   map[string]Profile
	executor   Executor
	root       string
	crypt      cipher.AEAD
	slots      chan struct{}
}
type record struct {
	Version     string          `json:"version"`
	ScopeHash   string          `json:"scope_hash"`
	ToolName    string          `json:"tool_name"`
	CallID      string          `json:"call_id"`
	Fingerprint string          `json:"fingerprint"`
	ProfileID   string          `json:"profile_id"`
	Status      string          `json:"status"`
	Result      *sandbox.Result `json:"result,omitempty"`
}

func New(controller string, public ed25519.PublicKey, profiles []Profile, executor Executor, root string, key []byte, maxConcurrent int) (*Server, error) {
	if controller == "" || len(controller) > 128 || len(public) != ed25519.PublicKeySize || executor == nil || !filepath.IsAbs(root) || len(key) != 32 || maxConcurrent < 1 || maxConcurrent > 8 || len(profiles) == 0 || len(profiles) > 16 {
		return nil, protocol.ErrPermit
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, protocol.ErrPermit
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	crypt, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	s := &Server{controller: controller, public: append(ed25519.PublicKey(nil), public...), profiles: map[string]Profile{}, executor: executor, root: root, crypt: crypt, slots: make(chan struct{}, maxConcurrent)}
	for _, p := range profiles {
		if p.ID == "" || len(p.ID) > 128 || strings.TrimSpace(p.ID) != p.ID || strings.ContainsAny(p.ID, "\x00\r\n") || len(p.ToolName) > 128 || !strings.HasPrefix(p.ToolName, "code.") || strings.TrimSpace(p.ToolName) != p.ToolName || strings.ContainsAny(p.ToolName, "\x00\r\n") || (p.Language != "python" && p.Language != "javascript" && p.Language != "shell") || p.Limits.Validate() != nil {
			return nil, protocol.ErrPermit
		}
		if _, found := s.profiles[p.ID]; found {
			return nil, protocol.ErrPermit
		}
		s.profiles[p.ID] = p
	}
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		s.fail(w, 405, "METHOD_NOT_ALLOWED")
		return
	}
	action := ""
	switch r.URL.Path {
	case "/v1/execute":
		action = "execute"
	case "/v1/receipt":
		action = "receipt"
	default:
		s.fail(w, 404, "NOT_FOUND")
		return
	}
	var input struct {
		Permit string `json:"permit"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 512<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF {
		s.fail(w, 400, "INVALID_REQUEST")
		return
	}
	p, err := protocol.Verify(input.Permit, s.public, s.controller, action, time.Now())
	if err != nil {
		s.fail(w, 403, "EXECUTION_PERMIT_DENIED")
		return
	}
	profile, found := s.profiles[p.ProfileID]
	if !found || profile.ToolName != p.ToolName || profile.Language != p.Language || profile.Limits != p.Limits {
		s.fail(w, 403, "CODE_PROFILE_DENIED")
		return
	}
	key := protocol.OperationKey(p)
	old, found, err := s.lookup(key, p)
	if err != nil {
		s.fail(w, 409, "CODE_RECEIPT_CONFLICT")
		return
	}
	if action == "receipt" || found {
		if !found {
			old.Status = "not_found"
		}
		s.reply(w, p, old)
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		s.fail(w, 429, "CODE_CAPACITY_EXCEEDED")
		return
	}
	claim := record{Version: "code-receipt/v1", ScopeHash: p.ScopeHash, ToolName: p.ToolName, CallID: p.CallID, Fingerprint: p.Fingerprint, ProfileID: p.ProfileID, Status: "running"}
	if err = s.writeExclusive(key+".claim", claim); err != nil {
		old, found, err = s.lookup(key, p)
		if err != nil || !found {
			s.fail(w, 503, "CODE_RECEIPT_UNAVAILABLE")
			return
		}
		s.reply(w, p, old)
		return
	}
	result, err := s.executor.Run(r.Context(), sandbox.Request{Language: p.Language, Code: p.Code, Limits: p.Limits})
	if err != nil || !result.ContainerRemoved {
		claim.Status = "unknown"
	} else {
		claim.Status = "completed"
		claim.Result = &result
	}
	// Append-only completion is encrypted at rest; claim is never deleted to
	// guess that an interrupted execution had no effects. No source/token is stored.
	if err = s.writeExclusive(key+".receipt", claim); err != nil {
		s.fail(w, 503, "CODE_RECEIPT_UNAVAILABLE")
		return
	}
	s.reply(w, p, claim)
}
func (s *Server) fail(w http.ResponseWriter, status int, code string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code}})
}
func (s *Server) reply(w http.ResponseWriter, p protocol.Permit, row record) {
	_ = json.NewEncoder(w).Encode(map[string]any{"version": "code-receipt/v1", "scope_hash": p.ScopeHash, "tool_name": p.ToolName, "call_id": p.CallID, "fingerprint": p.Fingerprint, "status": row.Status, "result": row.Result})
}
func (s *Server) writeExclusive(name string, row record) error {
	body, err := json.Marshal(row)
	if err != nil {
		return err
	}
	nonce := make([]byte, s.crypt.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	sealed := s.crypt.Seal(nonce, nonce, body, []byte(name))
	file, err := os.OpenFile(filepath.Join(s.root, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(sealed)
	syncErr := file.Sync()
	closeErr := file.Close()
	return errors.Join(writeErr, syncErr, closeErr)
}
func (s *Server) read(name string) (record, bool, error) {
	var row record
	file, err := os.Open(filepath.Join(s.root, name))
	if errors.Is(err, os.ErrNotExist) {
		return row, false, nil
	}
	if err != nil {
		return row, true, protocol.ErrPermit
	}
	// JSON escaping can enlarge two bounded output streams by up to six times.
	// Bound the read itself, not only the allocation after reading the whole file.
	body, readErr := io.ReadAll(io.LimitReader(file, (16<<20)+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(body) > 16<<20 || len(body) < s.crypt.NonceSize() {
		return row, true, protocol.ErrPermit
	}
	nonce := body[:s.crypt.NonceSize()]
	plain, err := s.crypt.Open(nil, nonce, body[s.crypt.NonceSize():], []byte(name))
	if err != nil {
		return row, true, protocol.ErrPermit
	}
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&row) != nil || decoder.Decode(new(any)) != io.EOF {
		return row, true, protocol.ErrPermit
	}
	return row, true, nil
}
func (s *Server) lookup(key string, p protocol.Permit) (record, bool, error) {
	row, found, err := s.read(key + ".receipt")
	if err != nil {
		return row, found, err
	}
	if !found {
		row, found, err = s.read(key + ".claim")
	}
	if err != nil {
		return row, found, err
	}
	if found && (row.Version != "code-receipt/v1" || row.ScopeHash != p.ScopeHash || row.CallID != p.CallID || row.ToolName != p.ToolName || row.Fingerprint != p.Fingerprint || row.ProfileID != p.ProfileID) {
		return row, true, protocol.ErrPermit
	}
	return row, found, nil
}
