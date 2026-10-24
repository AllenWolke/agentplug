package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/capability"
)

func externalKnowledgeProvider() (capability.KnowledgeProvider, error) {
	base, key, raw := strings.TrimSpace(os.Getenv("RAG_BASE_URL")), strings.TrimSpace(os.Getenv("RAG_API_KEY")), strings.TrimSpace(os.Getenv("RAG_KB_IDS"))
	if file := strings.TrimSpace(os.Getenv("RAG_API_KEY_FILE")); file != "" {
		data, err := os.ReadFile(file)
		if err != nil || len(data) > 8192 {
			return nil, errors.New("RAG credential file unavailable")
		}
		key = strings.TrimSpace(string(data))
	}
	if base == "" && key == "" && raw == "" {
		return nil, nil
	}
	if base == "" || key == "" || raw == "" {
		return nil, errors.New("RAG configuration requires endpoint, credential and knowledge-base IDs")
	}
	values := strings.Split(raw, ",")
	if strings.HasPrefix(raw, "[") {
		var numbers []json.Number
		decoder := json.NewDecoder(strings.NewReader(raw))
		decoder.UseNumber()
		if decoder.Decode(&numbers) != nil || decoder.Decode(new(any)) != io.EOF {
			return nil, errors.New("invalid RAG knowledge-base IDs")
		}
		values = nil
		for _, number := range numbers {
			values = append(values, number.String())
		}
	}
	ids := []uint64{}
	seen := map[uint64]bool{}
	for _, value := range values {
		id, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
		if err != nil || id == 0 || seen[id] {
			return nil, errors.New("invalid RAG knowledge-base ID")
		}
		ids = append(ids, id)
		seen[id] = true
	}
	client := &http.Client{Timeout: 70 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("RAG redirects forbidden") }}
	return capability.NewHTTPKnowledgeProvider(base, key, ids, client)
}
