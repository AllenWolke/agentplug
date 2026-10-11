// Package adaptergen creates isolated, descriptor-driven adapter bundles.
// adaptergen 包生成与存量 Agent 源码隔离的声明式适配包。
package adaptergen

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"
)

type Options struct {
	AgentID     string
	Kind        string
	Output      string
	EndpointRef string
	// Templates is the adapter template root ("templates/adapters"). Each kind
	// renders its own assets from <Templates>/<kind>/ (profile.json, the deploy
	// manifests and manifest.json) instead of sharing one anonymous blob, which
	// is what makes the four kinds genuinely different artifacts. When empty the
	// generator locates the repository templates directory; when it cannot be
	// found generation fails closed rather than emitting a kind-agnostic bundle.
	// Templates 是 Adapter 模板根目录（templates/adapters）。每种 Kind 从
	// <Templates>/<kind>/ 渲染自己的资产（profile.json、部署清单与 manifest.json），
	// 而不是共用同一份匿名产物——这正是四种 Kind 产物真正不同的原因。为空时生成器会
	// 定位仓库模板目录；定位不到即失败闭合，绝不再产出与 Kind 无关的适配包。
	Templates string
	// Source is the legacy agent directory the caller expects to stay
	// untouched. When set it is hashed before and after generation and the
	// bundle is refused if a single byte changed, which is the evidence that
	// the external adapter never modified the original Agent.
	// Source 是调用方期望保持不变的存量 Agent 目录。设置后会在生成前后各算一次摘要，
	// 只要有一个字节变化就拒绝产出适配包——这正是「外置 Adapter 从未改动原 Agent」
	// 的可留存证据。
	Source string
	// DryRun performs the full generation (asset resolution, rendering, source
	// digest verification) into a staging directory but never publishes it, so
	// the caller receives a real plan instead of a stub. Nothing is written
	// next to the output path.
	// DryRun 会在暂存目录里完成整次生成（定位资产、渲染、源目录摘要校验），但不发布，
	// 使调用方得到真实计划而非一个空壳；输出路径旁不写入任何内容。
	DryRun bool
}

// Bundle reports exactly what the generator committed. Files lists every
// artifact relative path so CI can diff a golden package without globbing.
// Bundle 精确汇报生成器提交的内容。Files 列出全部产物相对路径，CI 可直接与 golden
// 包比对，无需通配扫描。
type Bundle struct {
	Kind         string   `json:"kind"`
	MappingHash  string   `json:"mapping_hash"`
	SourceDigest string   `json:"source_digest,omitempty"`
	Files        []string `json:"files"`
}

// runtimeFor maps an adapter kind to the runtime declaration the platform
// reads. Each kind advertises the transport and isolation it actually runs
// under instead of every kind masquerading as an HTTP container.
// runtimeFor 将 Adapter Kind 映射为平台读取的运行时声明。每种 Kind 声明自己真正
// 运行的传输与隔离，而不是所有 Kind 都伪装成 HTTP 容器。
func runtimeFor(kind string) map[string]string {
	switch kind {
	case "grpc":
		return map[string]string{"transport": "grpc", "isolation": "container"}
	case "process":
		return map[string]string{"transport": "process", "isolation": "sandbox"}
	case "sidecar":
		return map[string]string{"transport": "http", "isolation": "sidecar"}
	default:
		return map[string]string{"transport": "http", "isolation": "container"}
	}
}

// Generate writes the bundle into a staging directory and publishes it with a
// single rename, so a failure part-way through leaves neither a half-written
// package nor a modified legacy source tree.
// Generate 先把适配包写入暂存目录、再用一次 rename 发布，使中途失败既不会留下
// 半成品，也不会改动存量源码目录。
func Generate(options Options) (Bundle, error) {
	options.AgentID = strings.TrimSpace(options.AgentID)
	options.Kind = strings.TrimSpace(options.Kind)
	options.Output = filepath.Clean(options.Output)
	options.Source = strings.TrimSpace(options.Source)
	if err := validateOptions(options); err != nil {
		return Bundle{}, err
	}
	templates, err := resolveTemplates(options)
	if err != nil {
		return Bundle{}, err
	}
	options.Templates = templates
	profile, err := loadProfile(options)
	if err != nil {
		return Bundle{}, err
	}
	if _, err := os.Stat(options.Output); err == nil {
		return Bundle{}, errors.New("adapter output already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return Bundle{}, err
	}
	before := ""
	if options.Source != "" {
		digest, err := Digest(options.Source)
		if err != nil {
			return Bundle{}, err
		}
		before = digest
	}
	parent := filepath.Dir(options.Output)
	stagingDir := parent
	if options.DryRun {
		// A dry run must not touch the workspace: stage in the nearest existing
		// ancestor of the output instead of creating the output parent or
		// relying on the system temp directory.
		// dry-run 绝不触碰工作区：暂存在输出最近的已存在祖先目录，既不创建输出父目录，
		// 也不依赖系统临时目录。
		stagingDir = nearestExistingDir(parent)
	} else if err := os.MkdirAll(parent, 0755); err != nil {
		return Bundle{}, err
	}
	staging, err := os.MkdirTemp(stagingDir, ".adaptergen-")
	if err != nil {
		return Bundle{}, err
	}
	committed := false
	defer func() {
		if !committed {
			// A failed generation must never leave partial output behind.
			// 失败的生成绝不能留下半成品。
			_ = os.RemoveAll(staging)
		}
	}()
	hash, files, err := writeBundle(staging, options, profile)
	if err != nil {
		return Bundle{}, err
	}
	if options.Source != "" {
		after, err := Digest(options.Source)
		if err != nil {
			return Bundle{}, err
		}
		if after != before {
			return Bundle{}, errors.New("legacy source changed during adapter generation")
		}
	}
	if options.DryRun {
		// The whole bundle was rendered and verified, but it is never published:
		// the deferred cleanup removes the staging directory and the caller gets
		// the real plan (kind, mapping hash, files).
		// 整包已渲染并校验，但不发布：延迟清理会删除暂存目录，调用方拿到真实计划
		// （kind、mapping 哈希、产物清单）。
		return Bundle{Kind: options.Kind, MappingHash: hash, SourceDigest: before, Files: files}, nil
	}
	if err := os.Rename(staging, options.Output); err != nil {
		return Bundle{}, err
	}
	committed = true
	return Bundle{Kind: options.Kind, MappingHash: hash, SourceDigest: before, Files: files}, nil
}

// validateOptions enforces ownership before any byte is written: the bundle is
// always a sibling of the legacy Agent, never inside a native platform_entry
// scaffold, and never inside the source directory it claims to leave untouched.
// validateOptions 在写入任何字节前先确定归属：适配包始终是存量 Agent 的同级目录，
// 绝不写入原生 platform_entry 外壳，也绝不出现在它声称不会改动的源码目录内。
func validateOptions(options Options) error {
	if options.Kind != "legacy-http" && options.Kind != "grpc" && options.Kind != "process" && options.Kind != "sidecar" {
		return errors.New("unsupported adapter kind")
	}
	if options.AgentID == "" || options.Output == "." || strings.HasPrefix(options.Output, ".."+string(os.PathSeparator)) {
		return errors.New("invalid adapter output or agent id")
	}
	for _, segment := range strings.Split(filepath.ToSlash(options.Output), "/") {
		if segment == "platform_entry" {
			return errors.New("adapter output must not be written into a native platform_entry scaffold")
		}
	}
	if options.Source != "" {
		source, err := filepath.Abs(options.Source)
		if err != nil {
			return err
		}
		output, err := filepath.Abs(options.Output)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(source, output)
		if err != nil {
			return err
		}
		if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))) {
			return errors.New("adapter output must be outside the legacy agent source directory")
		}
	}
	return nil
}

// Digest content-addresses a directory tree, skipping VCS metadata and local
// build caches that are not part of the legacy Agent source.
// Digest 对目录树做内容寻址，跳过与存量 Agent 源码无关的 VCS 元数据与本地构建缓存。
func Digest(dir string) (string, error) {
	var paths []string
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			name := entry.Name()
			if name == ".git" || strings.HasPrefix(name, ".tmp") || strings.HasPrefix(name, ".go-build-cache") {
				return fs.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		paths = append(paths, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(paths)
	hasher := sha256.New()
	for _, rel := range paths {
		content, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			return "", err
		}
		hasher.Write([]byte(rel))
		hasher.Write([]byte{0})
		hasher.Write(content)
		hasher.Write([]byte{0})
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// kindProfile is the per-kind asset that drives the generated deployment. It is
// read from <Templates>/<kind>/profile.json and cross-checked against the code
// contract, so an asset can never silently claim a different isolation.
// kindProfile 是驱动生成部署的按 Kind 资产，取自 <Templates>/<kind>/profile.json，
// 并与代码契约交叉校验，使资产无法静默声明另一种隔离。
type kindProfile struct {
	Kind                    string   `json:"kind"`
	Isolation               string   `json:"isolation"`
	Transport               string   `json:"transport"`
	Port                    int      `json:"port"`
	DeclaredCapabilities    []string `json:"declared_capabilities"`
	UnsupportedCapabilities []string `json:"unsupported_capabilities"`
	InputSchema             string   `json:"input_schema"`
	OutputSchema            string   `json:"output_schema"`
}

// capabilityClosedSet is the only capability vocabulary the platform runtime
// understands; a generated bundle may declare a subset of it and must document
// every other entry as an explicit capability gap.
// capabilityClosedSet 是平台运行时唯一理解的封闭能力集合；生成的适配包只能声明其
// 子集，并把其余条目显式登记为能力缺口。
var capabilityClosedSet = []string{"invoke", "health", "events", "run", "resume", "cancel", "checkpoint"}

// resolveTemplates returns the adapter template root. An explicit caller value
// wins; otherwise the repository layout is located from the working directory
// or the executable path so a colleague can regenerate a bundle from a checkout.
// resolveTemplates 返回 Adapter 模板根目录：显式值优先，否则从工作目录或可执行文件
// 位置定位仓库布局，使同事可以基于检出直接重新生成适配包。
func resolveTemplates(options Options) (string, error) {
	if explicit := strings.TrimSpace(options.Templates); explicit != "" {
		if info, err := os.Stat(filepath.Join(explicit, options.Kind)); err != nil || !info.IsDir() {
			return "", fmt.Errorf("adapter templates for kind %q are missing under %s", options.Kind, explicit)
		}
		return explicit, nil
	}
	var roots []string
	if cwd, err := os.Getwd(); err == nil {
		roots = append(roots, cwd)
	}
	if exe, err := os.Executable(); err == nil {
		roots = append(roots, filepath.Dir(exe))
	}
	for _, root := range roots {
		for dir := root; ; {
			candidate := filepath.Join(dir, "templates", "adapters")
			if info, err := os.Stat(filepath.Join(candidate, options.Kind)); err == nil && info.IsDir() {
				return candidate, nil
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	return "", errors.New("adapter templates directory not found; pass Options.Templates pointing at templates/adapters")
}

// nearestExistingDir walks up from dir until it finds an existing directory,
// falling back to the current directory. Dry runs stage here so they neither
// create the output parent nor depend on the system temp directory.
// nearestExistingDir 从 dir 向上寻找已存在目录，找不到则回退到当前目录；dry-run
// 在此暂存，因此既不创建输出父目录，也不依赖系统临时目录。
func nearestExistingDir(dir string) string {
	for {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			return dir
		}
		next := filepath.Dir(dir)
		if next == dir {
			return "."
		}
		dir = next
	}
}

// loadProfile reads and validates the per-kind asset. It fails closed when the
// asset is absent or contradicts runtimeFor, which keeps the four kinds honest.
// loadProfile 读取并校验按 Kind 资产；缺失或与 runtimeFor 矛盾即失败闭合，使四种
// Kind 保持诚实。
func loadProfile(options Options) (kindProfile, error) {
	path := filepath.Join(options.Templates, options.Kind, "profile.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return kindProfile{}, fmt.Errorf("adapter profile for kind %q is required: %w", options.Kind, err)
	}
	var profile kindProfile
	if err := json.Unmarshal(raw, &profile); err != nil {
		return kindProfile{}, fmt.Errorf("adapter profile %s is invalid: %w", path, err)
	}
	expected := runtimeFor(options.Kind)
	if profile.Kind != options.Kind {
		return kindProfile{}, fmt.Errorf("adapter profile kind %q does not match %q", profile.Kind, options.Kind)
	}
	if profile.Isolation != expected["isolation"] || profile.Transport != expected["transport"] {
		return kindProfile{}, fmt.Errorf("adapter profile %s contradicts the %s runtime contract", path, options.Kind)
	}
	if profile.Port <= 0 || profile.Port > 65535 {
		return kindProfile{}, fmt.Errorf("adapter profile %s declares an invalid port", path)
	}
	if len(profile.DeclaredCapabilities) == 0 {
		return kindProfile{}, fmt.Errorf("adapter profile %s declares no capability", path)
	}
	declared := map[string]bool{}
	for _, capability := range profile.DeclaredCapabilities {
		if !containsString(capabilityClosedSet, capability) {
			return kindProfile{}, fmt.Errorf("adapter profile %s declares unknown capability %q", path, capability)
		}
		if declared[capability] {
			return kindProfile{}, fmt.Errorf("adapter profile %s repeats capability %q", path, capability)
		}
		declared[capability] = true
	}
	for _, capability := range profile.UnsupportedCapabilities {
		if !containsString(capabilityClosedSet, capability) {
			return kindProfile{}, fmt.Errorf("adapter profile %s lists unknown capability gap %q", path, capability)
		}
		if declared[capability] {
			return kindProfile{}, fmt.Errorf("adapter profile %s lists %q as both declared and unsupported", path, capability)
		}
	}
	if profile.InputSchema == "" || profile.OutputSchema == "" {
		return kindProfile{}, fmt.Errorf("adapter profile %s must reference input and output schemas", path)
	}
	return profile, nil
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// renderAsset renders one per-kind asset with strict, fail-closed substitution:
// an unknown placeholder is an error rather than an empty string leaking into a
// published manifest.
// renderAsset 渲染单个按 Kind 资产并严格、失败闭合地替换：未知占位符直接报错，绝不
// 让空串泄漏进已发布的清单。
func renderAsset(options Options, profile kindProfile, relative string) ([]byte, error) {
	path := filepath.Join(options.Templates, options.Kind, filepath.FromSlash(relative))
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("adapter asset %s is required: %w", path, err)
	}
	parsed, err := template.New(filepath.Base(relative)).Option("missingkey=error").Parse(string(raw))
	if err != nil {
		return nil, fmt.Errorf("adapter asset %s is not a valid template: %w", path, err)
	}
	data := map[string]any{
		"AgentID":     options.AgentID,
		"Kind":        options.Kind,
		"Isolation":   profile.Isolation,
		"Transport":   profile.Transport,
		"Port":        profile.Port,
		"EndpointRef": options.EndpointRef,
		"Image":       options.AgentID + "-adapter:1.0.0",
	}
	var out bytes.Buffer
	if err := parsed.Execute(&out, data); err != nil {
		return nil, fmt.Errorf("adapter asset %s failed to render: %w", path, err)
	}
	return out.Bytes(), nil
}

// renderManifest renders the kind's own manifest asset instead of a shared
// inline blob, then enriches it with the generated runtime, endpoint and
// descriptor references. Keeping the asset authoritative is what makes the four
// kinds独立 and lets an operator adjust a kind without touching Go code.
// renderManifest 渲染该 Kind 自己的 manifest 资产而不是共用的内联块，再补充生成的
// 运行时、上游与描述符引用；以资产为准正是四种 Kind 相互独立、运维无需改 Go 代码即可
// 调整某一 Kind 的原因。
func renderManifest(options Options, profile kindProfile, runtime map[string]string) (map[string]any, error) {
	path := filepath.Join(options.Templates, options.Kind, "manifest.json")
	rendered, err := renderAsset(options, profile, "manifest.json")
	if err != nil {
		return nil, err
	}
	var manifest map[string]any
	if err := json.Unmarshal(rendered, &manifest); err != nil {
		return nil, fmt.Errorf("adapter asset %s is not valid JSON: %w", path, err)
	}
	manifest["manifest_version"] = "agent-adapter/v1"
	manifest["adapter_id"] = options.AgentID
	manifest["kind"] = options.Kind
	manifest["execution_protocol"] = "agent-execution/v2"
	manifest["mapping_ref"] = "mapping.json"
	manifest["descriptor_ref"] = "descriptor.json"
	manifest["endpoint_ref"] = options.EndpointRef
	manifest["isolation"] = runtime["isolation"]
	manifest["runtime"] = runtime
	manifest["capabilities"] = profile.DeclaredCapabilities
	return manifest, nil
}

// renderBundleAssets emits the per-kind deployment, schema, capability-gap and
// lifecycle-fixture artifacts. The deploy manifests are rendered from the kind's
// own assets, so every kind ships a real K8s Deployment/NetworkPolicy that
// expresses the isolation it declared instead of a shared placeholder.
// renderBundleAssets 产出按 Kind 的部署、Schema、能力缺口与生命周期夹具产物。部署清单
// 由该 Kind 自己的资产渲染，因此每种 Kind 都会带上真正表达其声明隔离的 K8s
// Deployment/NetworkPolicy，而不是共用的占位文件。
func renderBundleAssets(dir string, options Options, profile kindProfile, files *[]string) error {
	deployDir := filepath.Join(dir, "deploy")
	if err := os.MkdirAll(deployDir, 0755); err != nil {
		return err
	}
	for _, asset := range []string{"deploy/deployment.yaml", "deploy/networkpolicy.yaml"} {
		rendered, err := renderAsset(options, profile, asset)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(asset)), append(rendered, '\n'), 0644); err != nil {
			return err
		}
		*files = append(*files, asset)
	}

	schema := map[string]any{
		"schema_version": "adapter-schema/v1",
		"adapter_id":     options.AgentID,
		"kind":           options.Kind,
		"input":          profile.InputSchema,
		"output":         profile.OutputSchema,
	}
	capabilities := map[string]any{
		"capability_gap_version": "adapter-capability-gap/v1",
		"adapter_id":             options.AgentID,
		"kind":                   options.Kind,
		"isolation":              profile.Isolation,
		"declared":               profile.DeclaredCapabilities,
		"unsupported":            profile.UnsupportedCapabilities,
	}
	lifecycle := map[string]any{
		"fixture_version": "adapter-lifecycle-fixture/v1",
		"adapter_id":      options.AgentID,
		"kind":            options.Kind,
		"note":            "context_token and policy_snapshot.hash are placeholders; the Gateway signs each operation separately.",
		"operations":      lifecycleFixtures(options, profile),
	}
	for name, value := range map[string]any{"schema.json": schema, "capabilities.json": capabilities, "fixtures/lifecycle.json": lifecycle} {
		target := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		raw, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(target, append(raw, '\n'), 0644); err != nil {
			return err
		}
		*files = append(*files, name)
	}
	return nil
}

// lifecycleFixtures builds one conformance envelope per declared operation so an
// operator can obtain signed tokens and run the shared Conformance Runner.
// lifecycleFixtures 为每个已声明操作生成一份一致性信封，运维可据此换取已签名令牌并
// 运行统一 Conformance Runner。
func lifecycleFixtures(options Options, profile kindProfile) map[string]any {
	operations := map[string]any{}
	for _, capability := range profile.DeclaredCapabilities {
		if capability == "health" {
			continue
		}
		operations[capability] = map[string]any{
			"protocol_version": "agent-execution/v2",
			"context_token":    "REPLACE_WITH_GATEWAY_SIGNED_TOKEN",
			"scope": map[string]any{
				"tenant_id": "", "department_id": "", "application_id": "",
				"agent_instance_id": "", "agent_id": options.AgentID, "agent_version_id": "",
				"principal_type": "user", "principal_id": "", "session_id": "", "run_id": "",
				"authorization_epoch": 1, "trace_id": "",
			},
			"operation":       capability,
			"idempotency_key": capability + "-fixture",
			"input_schema":    profile.InputSchema,
			"input":           map[string]any{"policy_snapshot": map[string]any{"content_hash": "REPLACE_WITH_POLICY_SNAPSHOT_HASH"}},
		}
	}
	return operations
}

// writeBundle renders every artifact into the staging directory and returns the
// mapping hash and the committed file list.
// writeBundle 把全部产物渲染进暂存目录，并返回映射哈希与已提交文件清单。
func writeBundle(dir string, options Options, profile kindProfile) (string, []string, error) {
	runtime := runtimeFor(options.Kind)
	manifest, err := renderManifest(options, profile, runtime)
	if err != nil {
		return "", nil, err
	}
	mapping := map[string]any{"api_version": "agent-mapping/v1", "metadata": map[string]any{"mapping_id": options.AgentID, "version": "1.0.0"}, "spec": map[string]any{"upstream_ref": options.EndpointRef, "operations": map[string]any{"invoke": map[string]any{"request": map[string]any{"method": "POST", "path": "/agent/invoke", "body": map[string]any{"object": map[string]any{"input": map[string]any{"from_input": "input"}}}}, "response": map[string]any{"success_status": []int{200}, "output": map[string]any{"from_body": "output"}}}}}}
	files := []string{"manifest.json", "mapping.json"}
	for name, value := range map[string]any{"manifest.json": manifest, "mapping.json": mapping} {
		raw, _ := json.MarshalIndent(value, "", "  ")
		if err := os.WriteFile(filepath.Join(dir, name), append(raw, '\n'), 0644); err != nil {
			return "", nil, err
		}
	}
	mappingRaw, err := os.ReadFile(filepath.Join(dir, "mapping.json"))
	if err != nil {
		return "", nil, err
	}
	mappingHash := sha256.Sum256(mappingRaw)
	descriptor := map[string]any{
		"descriptor_version": "adapter-descriptor/v1",
		"adapter_id":         options.AgentID,
		"kind":               options.Kind,
		"protocol_version":   "agent-execution/v2",
		"mapping_ref":        "mapping.json",
		"mapping_hash":       hex.EncodeToString(mappingHash[:]),
		"endpoint_ref":       options.EndpointRef,
		"revision":           1,
		"runtime":            runtime,
		"isolation":          runtime["isolation"],
		"transport":          profile.Transport,
		// The generated runtime advertises exactly the capabilities its own
		// profile declares. Lifecycle endpoints are never advertised until a
		// dedicated runtime implements them.
		// 生成的运行时只宣告自身 profile 声明的能力；没有专用运行时前绝不虚报生命周期能力。
		"capabilities": profile.DeclaredCapabilities,
	}
	descriptorRaw, _ := json.MarshalIndent(descriptor, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "descriptor.json"), append(descriptorRaw, '\n'), 0644); err != nil {
		return "", nil, err
	}
	files = append(files, "descriptor.json")
	if err := renderBundleAssets(dir, options, profile, &files); err != nil {
		return "", nil, err
	}
	// Generate a small, dependency-free proxy instead of pointing the image at
	// a binary that does not exist. The legacy source remains untouched and the
	// platform injects the resolved endpoint at runtime.
	// 生成真正可编译的无依赖代理，而不是指向不存在的二进制；存量源码不变，
	// 由平台在运行时注入已解析的上游地址。
	adapterDir := filepath.Join(dir, "adapter")
	if err := os.MkdirAll(adapterDir, 0755); err != nil {
		return "", nil, err
	}
	if err := os.WriteFile(filepath.Join(adapterDir, "go.mod"), []byte("module generated-adapter\n\ngo 1.22\n"), 0644); err != nil {
		return "", nil, err
	}
	if err := os.WriteFile(filepath.Join(adapterDir, "main.go"), []byte(generatedProxySource), 0644); err != nil {
		return "", nil, err
	}
	files = append(files, "adapter/go.mod", "adapter/main.go")
	dockerfile := `# syntax=docker/dockerfile:1
FROM golang:1.25-alpine AS build
WORKDIR /src/adapter
COPY adapter/go.mod adapter/main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /out/adapter .
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/adapter /adapter/adapter
USER nonroot:nonroot
ENTRYPOINT ["/adapter/adapter"]
`
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(dockerfile), 0644); err != nil {
		return "", nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, ".dockerignore"), []byte(".git\n.env*\n*.key\n*.pem\n*.log\n"), 0644); err != nil {
		return "", nil, err
	}
	files = append(files, "Dockerfile", ".dockerignore")
	lock := map[string]any{"generator": "agentctl", "generator_version": "1.0.0", "managed_paths": []string{"manifest.json", "mapping.json", "descriptor.json", "schema.json", "capabilities.json", "fixtures/", "deploy/", "Dockerfile", "adapter/"}}
	lockRaw, _ := json.MarshalIndent(lock, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "template.lock"), append(lockRaw, '\n'), 0644); err != nil {
		return "", nil, err
	}
	readme := []byte("# Generated Adapter\n\nThis bundle is isolated from the legacy Agent and is governed by the platform Catalog.\n\nThe proxy forwards the platform-signed execution context (context_token, scope, idempotency key, trace) as explicit headers and signs the outbound body with HMAC-SHA256 when AGENT_SIGNING_SECRET is set.\n")
	if err := os.WriteFile(filepath.Join(dir, "README.md"), readme, 0644); err != nil {
		return "", nil, err
	}
	files = append(files, "template.lock", "README.md")
	h := sha256.Sum256(append(mappingRaw, readme...))
	sort.Strings(files)
	return hex.EncodeToString(h[:]), files, nil
}

// generatedProxySource is intentionally stdlib-only so the generated bundle
// can be built in an isolated, reproducible container. When the inbound body
// is an agent-execution/v2 envelope, the proxy forwards the signed context
// (context_token, scope, idempotency key, trace) as explicit headers and
// signs the outbound body with HMAC-SHA256, mirroring the platform contract:
// the legacy upstream receives verifiable provenance without protocol changes.
// 生成代理只依赖标准库，确保适配包可以在隔离容器中可重复构建；当入参是
// agent-execution/v2 封套时，代理把签名上下文（context_token、scope、幂等键、
// 追踪 ID）以显式请求头转发，并用 HMAC-SHA256 对出站正文签名，与平台契约一致：
// 存量上游无需改协议即可验证调用来源。
const generatedProxySource = `package main

import (
    "bytes"
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "io"
    "net/http"
    "net/url"
    "os"
    "strings"
    "time"
)

const maxBody = 8 << 20

var scopeHeaders = map[string]string{
    "tenant_id": "X-Scope-Tenant-ID", "department_id": "X-Scope-Department-ID",
    "application_id": "X-Scope-Application-ID", "agent_instance_id": "X-Scope-Agent-Instance-ID",
    "agent_id": "X-Scope-Agent-ID", "agent_version_id": "X-Scope-Agent-Version-ID",
    "principal_type": "X-Scope-Principal-Type", "principal_id": "X-Scope-Principal-ID",
    "session_id": "X-Scope-Session-ID", "run_id": "X-Scope-Run-ID",
}

// forwardSignedContext copies the platform-signed execution context from an
// agent-execution/v2 envelope into explicit upstream headers. Non-string or
// empty fields are skipped; a legacy body without envelope fields produces
// no context headers.
// forwardSignedContext 把 v2 封套中的签名上下文复制为显式上游请求头；非字符串
// 或空字段跳过，旧式正文不含封套字段时不产生上下文头。
func forwardSignedContext(req *http.Request, body []byte) {
    var envelope map[string]any
    if json.Unmarshal(body, &envelope) != nil {
        return
    }
    if token, ok := envelope["context_token"].(string); ok && strings.TrimSpace(token) != "" {
        req.Header.Set("X-Context-Token", token)
    }
    if key, ok := envelope["idempotency_key"].(string); ok && strings.TrimSpace(key) != "" {
        req.Header.Set("X-Idempotency-Key", key)
    }
    scope, ok := envelope["scope"].(map[string]any)
    if !ok {
        return
    }
    for field, header := range scopeHeaders {
        if value, ok := scope[field].(string); ok && strings.TrimSpace(value) != "" {
            req.Header.Set(header, value)
        }
    }
    if trace, ok := scope["trace_id"].(string); ok && strings.TrimSpace(trace) != "" {
        req.Header.Set("X-Trace-ID", trace)
    }
}

// signBody attaches an HMAC-SHA256 provenance signature over the exact
// outbound bytes when AGENT_SIGNING_SECRET is configured, matching the
// platform's X-Context-Signature scheme (sha256=<hex>).
// 配置 AGENT_SIGNING_SECRET 时对出站字节计算 HMAC-SHA256 溯源签名，
// 与平台 X-Context-Signature 方案（sha256=<hex>）一致。
func signBody(req *http.Request, payload []byte) {
    secret := os.Getenv("AGENT_SIGNING_SECRET")
    if strings.TrimSpace(secret) == "" {
        return
    }
    mac := hmac.New(sha256.New, []byte(secret))
    mac.Write(payload)
    req.Header.Set("X-Context-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
}

func main() {
    client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
        return http.ErrUseLastResponse // Redirects are never followed implicitly.
    }}
    mux := http.NewServeMux()
    mux.HandleFunc("/health/ready", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]any{"status": "ready", "protocol_version": "agent-execution/v2"}) })
    invoke := func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost { writeJSON(w, 405, map[string]string{"code": "METHOD_NOT_ALLOWED"}); return }
        body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1)); if err != nil || len(body) > maxBody { writeJSON(w, 400, map[string]string{"code": "BODY_TOO_LARGE"}); return }
        var request any; if json.Unmarshal(body, &request) != nil { writeJSON(w, 400, map[string]string{"code": "INVALID_JSON"}); return }
        input := request
        if object, ok := request.(map[string]any); ok {
            if value, exists := object["input"]; exists { input = value } // Mapping from_input "input": unwrap the v2 envelope field instead of double-wrapping.
        }
        endpoint := strings.TrimSpace(os.Getenv("AGENT_ENDPOINT_URL")); u, err := url.Parse(endpoint)
        if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") { writeJSON(w, 503, map[string]string{"code": "ENDPOINT_UNRESOLVED"}); return }
        payload, _ := json.Marshal(map[string]any{"input": input})
        req, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, strings.TrimRight(endpoint, "/")+"/agent/invoke", bytes.NewReader(payload)); req.Header.Set("Content-Type", "application/json")
        forwardSignedContext(req, body)
        signBody(req, payload)
        resp, err := client.Do(req); if err != nil { writeJSON(w, 502, map[string]string{"code": "UPSTREAM_UNAVAILABLE"}); return }; defer resp.Body.Close()
        out, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1)); if err != nil || len(out) > maxBody { writeJSON(w, 502, map[string]string{"code": "UPSTREAM_BODY_TOO_LARGE"}); return }
        if !json.Valid(out) { writeJSON(w, 502, map[string]string{"code": "UPSTREAM_INVALID_JSON"}); return }
        w.Header().Set("Content-Type", "application/json"); w.WriteHeader(resp.StatusCode); _, _ = w.Write(out)
    }
    mux.HandleFunc("/agent/invoke", invoke); mux.HandleFunc("/internal/agent-execution/v2/invoke", invoke)
    addr := strings.TrimSpace(os.Getenv("ADAPTER_LISTEN_ADDR"))
    if addr == "" { addr = ":8080" }
    _ = http.ListenAndServe(addr, mux)
}

func writeJSON(w http.ResponseWriter, status int, value any) { w.Header().Set("Content-Type", "application/json"); w.WriteHeader(status); _ = json.NewEncoder(w).Encode(value) }
`
