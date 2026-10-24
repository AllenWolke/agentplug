package capability

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lexagent/platform/internal/knowledge"
	"github.com/lexagent/platform/internal/telemetry"
	"go.opentelemetry.io/otel/trace"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type HTTPKnowledgeProvider struct {
	baseURL string
	apiKey  string
	kbIDs   []uint64
	client  *http.Client
}

func NewHTTPKnowledgeProvider(baseURL, apiKey string, kbIDs []uint64, client *http.Client) (*HTTPKnowledgeProvider, error) {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || parsed.Scheme != "http" && parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("invalid RAG_BASE_URL")
	}
	if strings.TrimSpace(apiKey) == "" || len(kbIDs) == 0 {
		return nil, errors.New("RAG API key and kb ids are required")
	}
	for _, id := range kbIDs {
		if id == 0 {
			return nil, errors.New("RAG knowledge base id must be positive")
		}
	}
	if client == nil {
		// RAG-Ops may perform embedding, hybrid retrieval and reranking in one
		// bounded request.  Keep a finite upper bound, but do not use a 10s
		// timeout that turns normal cold-index work into false provider outages.
		// RAG-Ops 可能在一次受控请求中完成向量化、混合检索和重排；保持有界，
		// 但不能用 10 秒把冷索引的正常耗时误报成 Provider 故障。
		client = &http.Client{Timeout: 70 * time.Second}
	}
	return &HTTPKnowledgeProvider{baseURL: strings.TrimRight(baseURL, "/"), apiKey: apiKey, kbIDs: append([]uint64(nil), kbIDs...), client: client}, nil
}

func (p *HTTPKnowledgeProvider) Search(ctx context.Context, h harnessContext, query knowledgeQuery) (result map[string]any, returnedErr error) {
	// A request ID is not a parent Span; propagate the actual W3C context.
	// 请求ID不是父Span；传播实际W3C上下文，不从业务ID伪造。
	ctx, span := telemetry.Start(ctx, "platform.knowledge.rag", trace.SpanKindClient)
	defer span.End()
	defer func() {
		if returnedErr != nil {
			telemetry.Failed(span, "RAG_PROVIDER_FAILED")
		}
	}()
	metadataFilter := map[string]any{"only_valid": true, "as_of": query.AsOf}
	kbIDs := p.kbIDs
	topK := query.TopK
	if query.GovernedDocuments {
		kbIDs = []uint64{}
		allowedDocuments := []map[string]string{}
		for _, doc := range query.Documents {
			if doc.ProviderID != "retrievalops" {
				continue
			}
			kb, err := strconv.ParseUint(doc.KnowledgeBaseID, 10, 64)
			if err != nil || kb == 0 {
				continue
			}
			configured := false
			for _, id := range p.kbIDs {
				if id == kb {
					configured = true
					break
				}
			}
			if !configured {
				continue
			}
			found := false
			for _, id := range kbIDs {
				if id == kb {
					found = true
					break
				}
			}
			if !found {
				kbIDs = append(kbIDs, kb)
			}
			allowedDocuments = append(allowedDocuments, map[string]string{"kb_id": doc.KnowledgeBaseID, "document_id": doc.ProviderDocumentID})
		}
		if len(kbIDs) == 0 {
			return nil, errKnowledgeDocumentAuthority
		}
		metadataFilter["allowed_documents"] = allowedDocuments
		metadataFilter["require_document_versions"] = true
		// The legacy upstream may ignore document metadata filters. Bound the
		// candidate pool and enforce our ACL before the platform's final Top-K.
		topK = 100
	}
	body, err := json.Marshal(map[string]any{
		"query":           query.Query,
		"top_k":           topK,
		"kb_ids":          kbIDs,
		"metadata_filter": metadataFilter,
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+"/v1/retrieve", strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.apiKey)
	telemetry.Inject(ctx, req.Header)
	if h.TraceID != "" {
		req.Header.Set("X-Trace-ID", h.TraceID)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("RAG provider request failed: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil || len(raw) > maxBody {
		return nil, errors.New("RAG provider response exceeds limit")
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return nil, errKnowledgeDocumentAuthority
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("RAG provider returned HTTP %d", resp.StatusCode)
	}
	var envelope map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	if err := decoder.Decode(&envelope); err != nil {
		return nil, errors.New("RAG provider returned invalid JSON")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("RAG provider returned invalid JSON")
	}
	data := envelope
	if nested, ok := envelope["data"].(map[string]any); ok {
		data = nested
	}
	requestID, _ := data["request_id"].(string)
	strategyVersion, _ := data["strategy_version"].(string)
	items, _ := data["items"].([]any)
	references := make([]map[string]any, 0, len(items))
	allowed := map[string]string{}
	for _, doc := range query.Documents {
		allowed[doc.ObjectID()] = doc.DocumentVersion
	}
	for _, rawItem := range items {
		item, ok := rawItem.(map[string]any)
		if !ok {
			continue
		}
		citation, _ := item["citation"].(map[string]any)
		source, _ := item["source"].(map[string]any)
		content := stringValue(item["content"])
		content, governed := parseGovernedMetadata(content)
		docID := firstString(governed, "doc_id", stringValue(citation["document_id"]))
		chunkID := firstString(governed, "clause", stringValue(citation["chunk_id"]))
		title := firstString(governed, "title", stringValue(citation["file_name"]))
		effectiveDate := firstString(governed, "effective_date", stringValue(item["effective_date"]))
		supersedes := governed["supersedes"]
		if supersedes == nil {
			supersedes = []any{}
		}
		version := firstString(governed, "document_version", stringValue(governed["kb_version"]))
		objectID := "retrievalops/" + stringValue(citation["kb_id"]) + "/" + stringValue(citation["document_id"])
		if query.GovernedDocuments {
			if allowed[objectID] == "" {
				continue
			}
			// 版本只能来自Provider的受控引用契约，不能把正文或策略当作实测版本。
			version = stringValue(citation["document_version"])
			if version == "" {
				return nil, &KnowledgeModelError{Status: 502, Code: "KNOWLEDGE_VERSION_UNAVAILABLE"}
			}
			if version != allowed[objectID] {
				return nil, &KnowledgeModelError{Status: 409, Code: "KNOWLEDGE_VERSION_CHANGED"}
			}
		}
		status := stringValue(governed["status"])
		applicable, err := knowledge.BusinessDate(map[string]string{"effective_date": effectiveDate, "valid_to": stringValue(governed["valid_to"]), "status": status}, query.AsOf)
		if err != nil {
			return nil, err
		}
		if !applicable {
			continue
		}
		references = append(references, map[string]any{
			"document_version":           version,
			"doc_id":                     docID,
			"provider_document_id":       stringValue(citation["document_id"]),
			"provider_knowledge_base_id": stringValue(citation["kb_id"]),
			"clause_or_chunk_id":         chunkID,
			"title":                      title,
			"content":                    content,
			"effective_date":             effectiveDate,
			"retrieval_score":            numberValue(item["score"]),
			"source":                     "retrievalops",
			"retrieval_request_id":       requestID,
			"kb_version":                 firstString(governed, "kb_version", firstString(governed, "document_version", strategyVersion)),
			"index_version":              stringValue(source["collection"]),
			"retriever_version":          stringValue(source["retriever_version"]),
			"valid_to":                   stringValue(governed["valid_to"]),
			"status":                     firstString(governed, "status", "effective"),
			"authority_level":            stringValue(governed["authority_level"]),
			"institution_types":          governed["institution_types"],
			"report_types":               governed["report_types"],
			"supersedes":                 supersedes,
			"topic_id":                   stringValue(governed["topic_id"]),
		})
	}
	return map[string]any{"references": references, "retrieved_sources": []string{"retrievalops"}, "failed_sources": []string{}, "partial_degraded": false, "request_id": requestID}, nil
}

// parseGovernedMetadata removes the transport-only LEXMETA header from the
// evidence body and returns the typed governance fields.  RAG-Ops stores this
// header in the chunk content so older retrieval contracts remain compatible;
// the platform must preserve the fields before passing evidence to an Agent.
// parseGovernedMetadata 去除证据正文中的传输元数据头并返回治理字段。RAG-Ops
// 为兼容旧协议把元数据放在 chunk 正文中，中台必须先提取再透传给 Agent。
func parseGovernedMetadata(content string) (string, map[string]any) {
	const marker = "LEXMETA:"
	index := strings.Index(content, marker)
	if index < 0 {
		return content, map[string]any{}
	}
	prefix := content[:index]
	rest := content[index+len(marker):]
	lineEnd := strings.IndexByte(rest, '\n')
	if lineEnd < 0 {
		return content, map[string]any{}
	}
	var metadata map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(rest[:lineEnd])), &metadata); err != nil {
		return content, map[string]any{}
	}
	return strings.TrimSpace(prefix + rest[lineEnd+1:]), metadata
}
