package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/lexagent/legacy-http-adapter/internal/descriptor"
	"github.com/lexagent/legacy-http-adapter/internal/planloader"
	"github.com/lexagent/legacy-http-adapter/internal/runtime"
	"github.com/lexagent/legacy-http-adapter/internal/target"
)

func main() {
	development := strings.EqualFold(os.Getenv("APP_ENV"), "development")

	var (
		base                *url.URL
		path                string
		limits              descriptor.Limits
		expectedMappingHash string
		expectedMappingRef  string
		mappingRequired     bool
		planPath            string
		planPublicKeyB64    string
		descriptorRevision  uint64
		eventsPath          string
	)
	if descriptorPath := strings.TrimSpace(os.Getenv("ADAPTER_DESCRIPTOR")); descriptorPath != "" {
		d, descriptorErr := descriptor.Load(descriptorPath)
		if descriptorErr != nil {
			log.Fatal(descriptorErr)
		}
		path = d.Path
		expectedMappingHash = strings.TrimSpace(d.MappingHash)
		expectedMappingRef = strings.TrimPrefix(strings.TrimSpace(d.MappingRef), "mapping://")
		mappingRequired = expectedMappingHash != "" || strings.TrimSpace(d.MappingRef) != ""
		limits = d.Limits
		planPath = strings.TrimSpace(d.PlanPath)
		planPublicKeyB64 = strings.TrimSpace(d.PlanPublicKey)
		eventsPath = strings.TrimSpace(d.EventsPath)
		if d.Revision > 0 {
			descriptorRevision = uint64(d.Revision)
		}
		if strings.TrimSpace(d.Endpoint) != "" {
			// The published descriptor is the authoritative upstream address.
			// Environment variables remain only as a development fallback for a
			// descriptor that predates the endpoint field. / 已发布 Descriptor 是
			// 权威上游地址；环境变量仅作为未携带 endpoint 字段的旧描述符的开发回退。
			resolved, endpointErr := target.Validate(d.Endpoint, development)
			if endpointErr != nil {
				log.Fatal(endpointErr)
			}
			base = resolved
		}
	}
	if base == nil {
		fallback, fallbackErr := target.Validate(os.Getenv("LEGACY_BASE_URL"), development)
		if fallbackErr != nil {
			log.Fatal(fallbackErr)
		}
		base = fallback
	}
	if path == "" {
		path = os.Getenv("LEGACY_INVOKE_PATH")
	}
	if path == "" || !strings.HasPrefix(path, "/") || strings.Contains(path, "..") {
		log.Fatal("LEGACY_INVOKE_PATH must be pre-registered")
	}
	key, err := base64.StdEncoding.DecodeString(os.Getenv("PLATFORM_CONTEXT_PUBLIC_KEY"))
	if err != nil || len(key) != ed25519.PublicKeySize {
		log.Fatal("PLATFORM_CONTEXT_PUBLIC_KEY is required")
	}
	// The registered plan document is the adapter's own source of truth: it is
	// verified (signature, pinned hash, revision) at startup and refreshed in the
	// background, and a failed refresh keeps the last-known-good revision rather
	// than dropping a running adapter. / 已登记的计划文档是 Adapter 自身的权威来源：
	// 启动时校验（签名、固定哈希、版本）、后台定期刷新，刷新失败保留 LKG 而不让
	// 运行中的 Adapter 掉线。
	var plans *planloader.Loader
	if planPath != "" {
		plans = &planloader.Loader{Path: planPath, ExpectedHash: expectedMappingHash, MinRevision: descriptorRevision}
		if planPublicKeyB64 != "" {
			planKey, decodeErr := base64.StdEncoding.DecodeString(planPublicKeyB64)
			if decodeErr != nil || len(planKey) != ed25519.PublicKeySize {
				log.Fatal("descriptor plan_public_key must be a base64 ed25519 public key")
			}
			plans.PublicKey = ed25519.PublicKey(planKey)
		}
		if _, refreshErr := plans.Refresh(); refreshErr != nil {
			log.Fatal(refreshErr)
		}
		go func() {
			ticker := time.NewTicker(planRefreshInterval())
			defer ticker.Stop()
			for range ticker.C {
				if _, refreshErr := plans.Refresh(); refreshErr != nil {
					log.Printf("mapping plan refresh failed, keeping revision %d: %v", plans.Revision(), refreshErr)
				}
			}
		}()
	}
	handler := runtime.NewHandler(runtime.Config{
		Development:      development,
		Upstream:         base,
		Path:             path,
		EventsPath:       eventsPath,
		Limits:           limits,
		ExpectedHash:     expectedMappingHash,
		ExpectedRef:      expectedMappingRef,
		MappingRequired:  mappingRequired,
		Plans:            plans,
		ContextPublicKey: ed25519.PublicKey(key),
		ContextIssuer:    os.Getenv("PLATFORM_CONTEXT_ISSUER"),
		AgentID:          os.Getenv("AGENT_ID"),
		MaxBody:          runtime.DefaultMaxBody,
	})
	server := &http.Server{Addr: ":8080", Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(server.ListenAndServe())
}

// planRefreshInterval reads the configured plan refresh cadence. It defaults to
// a minute and never returns a non-positive duration, so an operator cannot
// accidentally disable refresh and pin the adapter to a stale plan forever.
// planRefreshInterval 读取配置的计划刷新周期：默认一分钟且永不返回非正值，使运维
// 无法意外关闭刷新、把 Adapter 永久钉在过期计划上。
func planRefreshInterval() time.Duration {
	seconds, err := strconv.Atoi(strings.TrimSpace(os.Getenv("PLAN_REFRESH_SECONDS")))
	if err != nil || seconds <= 0 {
		return 60 * time.Second
	}
	return time.Duration(seconds) * time.Second
}
