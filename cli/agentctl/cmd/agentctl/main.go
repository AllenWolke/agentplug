package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/lexagent/agentctl/internal/adaptergen"
	agentbuild "github.com/lexagent/agentctl/internal/build"
	legacyinspect "github.com/lexagent/agentctl/internal/inspect"
	agenttemplate "github.com/lexagent/agentctl/internal/template"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

type result struct {
	OK      bool   `json:"ok"`
	Command string `json:"command"`
	Data    any    `json:"data,omitempty"`
	Errors  []item `json:"errors"`
}
type item struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Path    string `json:"path,omitempty"`
}

func main() {
	if len(os.Args) < 2 {
		emit(result{Command: "help", Errors: []item{{Code: "USAGE", Message: "agentctl template|create|inspect|validate|generate-adapter|test|package|publish|upgrade"}}}, 2)
		return
	}
	cmd := os.Args[1]
	args, dryRun := withoutDryRun(os.Args[2:])
	// dry-run must exercise the same planning and validation as a real run and
	// report what would change, then stop before any write or network call.
	// Upgrade already carries its own --dry-run flag through to the planner.
	// dry-run 必须执行与真实运行相同的规划与校验并汇报将发生的变化，然后在任何写盘或
	// 网络调用之前停下；upgrade 已把 --dry-run 透传给规划器。
	if dryRun && cmd == "upgrade" {
		args = append(args, "--dry-run")
	}
	var out result
	var code int
	switch cmd {
	case "template":
		out, code = templateCommand(args)
	case "create":
		out, code = create(args, dryRun)
	case "inspect":
		out, code = inspect(args)
	case "validate":
		out, code = validate(args)
	case "generate-adapter":
		out, code = generateAdapter(args, dryRun)
	case "test":
		out, code = testAgent(args)
	case "package":
		out, code = packageAgent(args, dryRun)
	case "publish":
		out, code = publish(args, dryRun)
	case "upgrade":
		out, code = upgrade(args)
	default:
		out = result{Command: cmd, Errors: []item{{Code: "UNKNOWN_COMMAND", Message: cmd}}}
		code = 2
	}
	emit(out, code)
}

func templateCommand(args []string) (result, int) {
	if len(args) == 0 {
		return fail("template", "USAGE", "template list|get|verify"), 2
	}
	root := resolveTemplateRoot()
	if root == "" {
		return fail("template", "READ_FAILED", "template registry unavailable"), 1
	}
	switch args[0] {
	case "list":
		entries, err := os.ReadDir(root)
		if err != nil {
			return fail("template list", "READ_FAILED", err.Error()), 1
		}
		items := make([]string, 0, len(entries))
		for _, entry := range entries {
			if entry.IsDir() {
				items = append(items, entry.Name())
			}
		}
		sort.Strings(items)
		return result{OK: true, Command: "template list", Data: map[string]any{"templates": items}}, 0
	case "get":
		if len(args) < 2 {
			return fail("template get", "USAGE", "template get <id>"), 2
		}
		path := filepath.Join(root, filepath.Clean(args[1]))
		if !strings.HasPrefix(filepath.Clean(path), filepath.Clean(root)+string(os.PathSeparator)) {
			return fail("template get", "PATH", "template path escapes registry"), 2
		}
		info, err := os.Stat(path)
		if err != nil || !info.IsDir() {
			return fail("template get", "NOT_FOUND", args[1]), 1
		}
		return result{OK: true, Command: "template get", Data: map[string]any{"id": args[1], "path": path}}, 0
	case "verify":
		if root == "" {
			return fail("template verify", "READ_FAILED", "template registry unavailable"), 1
		}
		if _, err := os.Stat(filepath.Join(root, "registry", "index.yaml")); err != nil {
			return fail("template verify", "REGISTRY_INVALID", err.Error()), 1
		}
		return result{OK: true, Command: "template verify", Data: map[string]any{"status": "verified", "registry": root}}, 0
	default:
		return fail("template", "UNKNOWN_COMMAND", args[0]), 2
	}
}

// withoutDryRun extracts the global flags every command shares. Output is
// always agentctl-output/v1 JSON, so --json is accepted (and ignored) on every
// command rather than only on upgrade; --dry-run is hoisted so planning runs
// without writes.
// withoutDryRun 抽取所有命令共享的全局标志。输出始终是 agentctl-output/v1 JSON，
// 因此 --json 在所有命令上都被接受（并忽略），而不是只在 upgrade 上；--dry-run 被
// 提升出来，使规划得以在不写盘的情况下运行。
func withoutDryRun(args []string) ([]string, bool) {
	clean := make([]string, 0, len(args))
	dry := false
	for _, arg := range args {
		switch arg {
		case "--dry-run":
			dry = true
		case "--json":
		default:
			clean = append(clean, arg)
		}
	}
	return clean, dry
}
func emit(v result, code int) {
	if v.Errors == nil {
		v.Errors = []item{}
	}
	if !v.OK && len(v.Errors) == 0 {
		v.Errors = []item{{Code: "FAILED", Message: "command failed"}}
	}
	raw, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(raw))
	if code != 0 {
		os.Exit(code)
	}
}
func create(args []string, dryRun bool) (result, int) {
	f := flag.NewFlagSet("create", flag.ContinueOnError)
	f.SetOutput(os.Stderr)
	lang := f.String("language", "python", "language")
	template := f.String("template", "", "template id (for example python-langgraph)")
	name := f.String("name", "agent", "agent name")
	out := f.String("output", "", "output directory")
	force := f.Bool("force", false, "update a directory previously generated by agentctl")
	if f.Parse(args) != nil {
		return result{Command: "create"}, 2
	}
	if *out == "" {
		return fail("create", "OUTPUT_REQUIRED", "--output is required"), 2
	}
	if filepath.IsAbs(*out) {
		return fail("create", "OUTPUT_PATH", "output must be relative to current workspace"), 2
	}
	if *lang != "python" && *lang != "go" && *lang != "java" {
		return fail("create", "LANGUAGE", "unsupported language"), 2
	}
	if *template != "" && !templateLanguage(*template, *lang) {
		return fail("create", "TEMPLATE", "template does not match language"), 2
	}
	target := filepath.Clean(*out)
	if target == "." || strings.HasPrefix(target, "..") {
		return fail("create", "OUTPUT_PATH", "output escapes workspace"), 2
	}
	if info, err := os.Stat(target); err == nil {
		if !info.IsDir() || !*force {
			return fail("create", "OUTPUT_EXISTS", "refusing to overwrite existing directory"), 2
		}
		if _, lockErr := os.Stat(filepath.Join(target, "template.lock")); lockErr != nil {
			return fail("create", "OUTPUT_NOT_OWNED", "--force requires an agentctl template.lock"), 2
		}
	}
	// Render into a sibling temporary directory and publish with one rename so a
	// failed generation never leaves a half-created Agent. / 先写临时目录再一次
	// 性发布，避免失败后留下半成品 Agent。
	parent := filepath.Dir(target)
	stagingDir := parent
	if dryRun {
		// A dry run renders the complete project and reports the exact file list,
		// yet stages beside the output rather than in the system temp directory,
		// so it neither creates workspace directories nor depends on temp space.
		// dry-run 渲染完整项目并汇报确切文件清单，但暂存在输出旁边而非系统临时目录，
		// 因此既不创建任何工作区目录，也不依赖临时空间。
		stagingDir = nearestExistingDir(parent)
	} else if err := os.MkdirAll(parent, 0755); err != nil {
		return fail("create", "CREATE_FAILED", err.Error()), 1
	}
	workTarget, err := os.MkdirTemp(stagingDir, ".agentctl-create-*")
	if err != nil {
		return fail("create", "CREATE_FAILED", err.Error()), 1
	}
	defer os.RemoveAll(workTarget)
	if err := os.MkdirAll(filepath.Join(workTarget, "domain"), 0755); err != nil {
		return fail("create", "CREATE_FAILED", err.Error()), 1
	}
	for _, dir := range []string{"schemas", "graph", "prompts", "eval/datasets", "eval/scorers", "eval/negative_cases", "platform_entry", "tests"} {
		if err := os.MkdirAll(filepath.Join(workTarget, filepath.FromSlash(dir)), 0755); err != nil {
			return fail("create", "CREATE_FAILED", err.Error()), 1
		}
	}
	if *template == "" {
		*template = defaultTemplate(*lang)
	}
	// Copy only the immutable, reviewed template payload. The generated
	// project never executes template hooks or writes outside target.
	// 只复制经过审核的不可变模板内容；生成过程不执行 Hook，也不写出目标目录。
	templateRoot := resolveTemplateRoot()
	if templateRoot == "" {
		return fail("create", "TEMPLATE_ROOT", "templates directory was not found"), 1
	}
	if err := copyTemplate(templateRoot, *template, workTarget); err != nil {
		return fail("create", "TEMPLATE_COPY_FAILED", err.Error()), 1
	}
	// Capability and schema declarations are inherited from the template's own
	// manifest (already copied above): the scaffold must never claim lifecycle
	// legs the template does not implement, nor hide legs it does. Identity
	// fields stay per-project. When no template manifest is present, fall back
	// to the conservative invoke-only declaration.
	// 能力与 schema 声明继承自模板自身的 manifest（上文已复制）：脚手架绝不声明模板
	// 未实现的生命周期腿，也不隐藏模板已实现的腿；身份字段按项目生成。模板 manifest
	// 缺失时，回退到保守的仅 invoke 声明。
	capabilities := []string{"invoke"}
	schemas := map[string]any{"input": "schema://" + slug(*name) + "/input/v1", "output": "schema://" + slug(*name) + "/output/v1", "event": "schema://" + slug(*name) + "/event/v1", "checkpoint": "schema://" + slug(*name) + "/checkpoint/v1"}
	if inherited, err := readInheritedDeclarations(filepath.Join(workTarget, "manifest.json"), slug(*name)); err == nil {
		capabilities = inherited.Capabilities
		schemas = inherited.Schemas
	}
	manifest := map[string]any{
		"manifest_version": "agent-manifest/v1", "agent_id": slug(*name), "version": "0.1.0",
		"execution_protocols": []string{"agent-execution/v2"}, "capabilities": capabilities,
		"schemas":  schemas,
		"runtime":  map[string]any{"transport": "http", "isolation": "container", "health_path": "/health/ready"},
		"metadata": map[string]string{"language": *lang, "template_id": *template, "template_version": "1.0.0"},
	}
	if err := writeJSON(filepath.Join(workTarget, "manifest.json"), manifest); err != nil {
		return fail("create", "CREATE_FAILED", err.Error()), 1
	}
	files := map[string]string{
		"README.md":           "# " + *name + "\n\nBusiness-owned code belongs under domain/graph/prompts/eval. The platform owns IAM, run state, model and tool gateways.\n",
		"schemas/input.json":  "{\"type\":\"object\",\"additionalProperties\":true}\n",
		"schemas/output.json": "{\"type\":\"object\",\"additionalProperties\":true}\n",
		"template.lock":       "{\n  \"template_id\": \"" + *template + "\",\n  \"template_version\": \"1.0.0\",\n  \"managed_paths\": [\"manifest.json\", \"platform_entry/\"],\n  \"business_paths\": [\"domain/\", \"graph/\", \"prompts/\", \"eval/\"]\n}\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(workTarget, filepath.FromSlash(name)), []byte(content), 0644); err != nil {
			return fail("create", "CREATE_FAILED", err.Error()), 1
		}
	}
	ownershipLock, lockErr := agenttemplate.BuildOwnershipLock(workTarget, *template, "1.0.0")
	if lockErr != nil {
		return fail("create", "LOCK_BUILD_FAILED", lockErr.Error()), 1
	}
	if lockErr := writeJSON(filepath.Join(workTarget, "template.lock"), ownershipLock); lockErr != nil {
		return fail("create", "LOCK_WRITE_FAILED", lockErr.Error()), 1
	}
	if dryRun {
		files, listErr := listFiles(workTarget)
		if listErr != nil {
			return fail("create", "CREATE_FAILED", listErr.Error()), 1
		}
		return result{OK: true, Command: "create", Data: map[string]any{"dry_run": true, "path": target, "language": *lang, "template": *template, "files": files, "would_change": true}}, 0
	}
	if info, statErr := os.Stat(target); statErr == nil && info.IsDir() && *force {
		backup, mkErr := os.MkdirTemp(parent, ".agentctl-backup-*")
		if mkErr != nil {
			return fail("create", "PUBLISH_FAILED", mkErr.Error()), 1
		}
		_ = os.Remove(backup)
		if err := os.Rename(target, backup); err != nil {
			return fail("create", "PUBLISH_FAILED", err.Error()), 1
		}
		if err := os.Rename(workTarget, target); err != nil {
			_ = os.Rename(backup, target)
			return fail("create", "PUBLISH_FAILED", err.Error()), 1
		}
		_ = os.RemoveAll(backup)
	} else if err := os.Rename(workTarget, target); err != nil {
		return fail("create", "PUBLISH_FAILED", err.Error()), 1
	}
	return result{OK: true, Command: "create", Data: map[string]any{"path": target, "language": *lang}}, 0
}

// nearestExistingDir walks up from dir until it finds an existing directory,
// falling back to the current directory. Dry runs stage here so they never
// create directories in the workspace.
// nearestExistingDir 从 dir 向上寻找已存在目录，找不到则回退到当前目录；dry-run
// 在此暂存，因此不会在工作区创建任何目录。
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

// listFiles returns every file under dir as a sorted, slash-separated relative
// path so a dry run can report the exact ownership of its plan.
// listFiles 返回 dir 下全部文件的有序斜杠相对路径，使 dry-run 能精确汇报计划产物。
func listFiles(dir string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		files = append(files, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

func resolveTemplateRoot() string {
	if root := strings.TrimSpace(os.Getenv("AGENTCTL_TEMPLATE_ROOT")); root != "" {
		if info, err := os.Stat(root); err == nil && info.IsDir() {
			return root
		}
	}
	var candidates []string
	if wd, err := os.Getwd(); err == nil {
		dir := wd
		for i := 0; i < 6; i++ {
			candidates = append(candidates, filepath.Join(dir, "templates"))
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	if _, file, _, ok := runtime.Caller(0); ok {
		candidates = append(candidates, filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "templates"))
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(filepath.Join(candidate, "python-generic")); err == nil {
			return candidate
		}
	}
	return ""
}

// inheritedDeclarations carries only the template-owned parts of a manifest.
// / inheritedDeclarations 只承载 manifest 中归模板所有的声明部分。
type inheritedDeclarations struct {
	Capabilities []string       `json:"capabilities"`
	Schemas      map[string]any `json:"schemas"`
}

// readInheritedDeclarations loads the template's own manifest from the staged
// project and rewrites {{agent_id}} placeholders to the generated identity.
// A missing or unreadable file yields an error so the caller falls back to
// the conservative invoke-only default — template absence must never
// fabricate lifecycle capabilities.
// readInheritedDeclarations 从已暂存的项目里读取模板自身的 manifest，并把
// {{agent_id}} 占位符改写为生成的身份。文件缺失或不可读时返回错误，调用方回退
// 到保守的仅 invoke 默认——模板缺失绝不许凭空制造生命周期能力。
func readInheritedDeclarations(path, agentID string) (*inheritedDeclarations, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var declarations inheritedDeclarations
	if err := json.Unmarshal(data, &declarations); err != nil {
		return nil, err
	}
	if len(declarations.Capabilities) == 0 || len(declarations.Schemas) == 0 {
		return nil, fmt.Errorf("template manifest lacks capability or schema declarations")
	}
	for key, value := range declarations.Schemas {
		if schema, ok := value.(string); ok {
			declarations.Schemas[key] = strings.ReplaceAll(schema, "{{agent_id}}", agentID)
		}
	}
	return &declarations, nil
}

// skippedTemplateEntry never travels into a generated project: local test runs
// regenerate caches beside the sources (Python .pytest_cache/__pycache__/*.pyc,
// Maven target/ output), and scaffolding must not copy that noise.
// skippedTemplateEntry 绝不进入生成项目：本地测试会在源码旁重新生成缓存
// （Python 的 .pytest_cache/__pycache__/*.pyc、Maven 的 target/ 产物），脚手架
// 不得复制这些噪声。
func skippedTemplateEntry(name string, isDir bool) bool {
	if isDir {
		return name == ".pytest_cache" || name == "__pycache__" || name == "target"
	}
	return strings.HasSuffix(name, ".pyc") || strings.HasSuffix(name, ".class")
}

func copyTemplate(root, template, target string) error {
	source := filepath.Join(root, filepath.FromSlash(template))
	info, err := os.Stat(source)
	if err != nil {
		return fmt.Errorf("template %s was not found under %s", template, root)
	}
	if !info.IsDir() {
		return fmt.Errorf("template is not a directory: %s", template)
	}
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if skippedTemplateEntry(entry.Name(), entry.IsDir()) {
			if entry.IsDir() {
				// Skip the cache directory entirely; its children never reach
				// WalkDir's callback. / 整体跳过缓存目录，其子项不再回调。
				return fs.SkipDir
			}
			// Skip only this cache file, never its siblings.
			// 只跳过该缓存文件，绝不影响同级其他文件。
			return nil
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
			return fmt.Errorf("template path escapes root")
		}
		dest := filepath.Join(target, rel)
		if entry.IsDir() {
			return os.MkdirAll(dest, 0755)
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("template symlink is not allowed: %s", rel)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if len(data) > 8<<20 {
			return fmt.Errorf("template file too large: %s", rel)
		}
		return os.WriteFile(dest, data, 0644)
	})
}

func defaultTemplate(language string) string {
	if language == "go" {
		return "go-generic"
	}
	if language == "java" {
		return "java-generic"
	}
	return "python-generic"
}
func templateLanguage(template, language string) bool {
	prefix := strings.SplitN(template, "-", 2)[0]
	return prefix == language
}
func slug(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
			b.WriteRune(r)
		} else if b.Len() > 0 {
			b.WriteRune('-')
		}
	}
	s := strings.Trim(b.String(), "-")
	if len(s) < 3 {
		s = "agent"
	}
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}
func inspect(args []string) (result, int) {
	f := flag.NewFlagSet("inspect", flag.ContinueOnError)
	root := f.String("path", ".", "agent path")
	if f.Parse(args) != nil {
		return result{Command: "inspect"}, 2
	}
	report, err := legacyinspect.Run(*root)
	if err != nil {
		return result{OK: false, Command: "inspect", Data: report, Errors: []item{{Code: "READ_FAILED", Message: err.Error()}}}, 1
	}
	if len(report.Files) == 0 {
		report.Findings = append(report.Findings, legacyinspect.Finding{ID: "files", Status: legacyinspect.Unknown, Summary: "agent directory contains no files"})
	}
	return result{OK: true, Command: "inspect", Data: report}, 0
}
func validate(args []string) (result, int) {
	f := flag.NewFlagSet("validate", flag.ContinueOnError)
	root := f.String("path", ".", "agent path")
	if f.Parse(args) != nil {
		return result{Command: "validate"}, 2
	}
	manifest := filepath.Join(*root, "manifest.json")
	raw, err := os.ReadFile(manifest)
	if err != nil {
		return fail("validate", "MANIFEST_MISSING", err.Error()), 1
	}
	var m struct {
		ManifestVersion    string            `json:"manifest_version"`
		AgentID            string            `json:"agent_id"`
		Version            string            `json:"version"`
		ExecutionProtocols []string          `json:"execution_protocols"`
		Capabilities       []string          `json:"capabilities"`
		Schemas            map[string]string `json:"schemas"`
		Runtime            map[string]string `json:"runtime"`
		Metadata           map[string]string `json:"metadata"`
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if dec.Decode(&m) != nil {
		return fail("validate", "MANIFEST_INVALID", "manifest must be JSON"), 1
	}
	if m.ManifestVersion != "agent-manifest/v1" || !validSlug(m.AgentID) || m.Version == "" || len(m.ExecutionProtocols) == 0 || !containsString(m.ExecutionProtocols, "agent-execution/v2") || len(m.Capabilities) == 0 || m.Schemas["input"] == "" || m.Schemas["output"] == "" || m.Runtime["transport"] == "" || m.Runtime["isolation"] == "" {
		return fail("validate", "MANIFEST_INVALID", "agent_id and protocol_version are required"), 1
	}
	if _, err := os.Stat(filepath.Join(*root, "template.lock")); err != nil {
		return fail("validate", "LOCK_MISSING", "template.lock is required"), 1
	}
	return result{OK: true, Command: "validate", Data: map[string]any{"manifest": manifest}}, 0
}
func validSlug(s string) bool {
	if len(s) < 3 || len(s) > 64 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}
func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
func generateAdapter(args []string, dryRun bool) (result, int) {
	f := flag.NewFlagSet("generate-adapter", flag.ContinueOnError)
	name := f.String("name", "legacy-agent", "legacy agent id")
	out := f.String("output", "", "adapter output")
	kind := f.String("kind", "legacy-http", "adapter kind")
	endpoint := f.String("endpoint", "endpoint://legacy-agent", "registered upstream endpoint reference")
	source := f.String("source", "", "legacy agent source directory whose digest must stay unchanged")
	templates := f.String("templates", "", "adapter template root; defaults to the repository templates/adapters directory")
	if f.Parse(args) != nil {
		return result{Command: "generate-adapter"}, 2
	}
	if *out == "" {
		return fail("generate-adapter", "OUTPUT_REQUIRED", "--output is required"), 2
	}
	if *kind != "legacy-http" && *kind != "grpc" && *kind != "process" && *kind != "sidecar" {
		return fail("generate-adapter", "KIND", "unsupported adapter kind"), 2
	}
	bundle, err := adaptergen.Generate(adaptergen.Options{AgentID: slug(*name), Kind: *kind, Output: *out, EndpointRef: *endpoint, Source: *source, Templates: *templates, DryRun: dryRun})
	if err != nil {
		return fail("generate-adapter", "CREATE_FAILED", err.Error()), 1
	}
	data := map[string]any{"path": *out, "kind": bundle.Kind, "mapping_hash": bundle.MappingHash, "files": bundle.Files}
	if dryRun {
		// The plan is fully rendered and verified; report it as such so CI can
		// distinguish a real dry run from the previous stub response.
		// 计划已完整渲染并校验，如实汇报，使 CI 能把真实 dry-run 与旧空壳响应区分开。
		data["dry_run"] = true
		data["would_change"] = true
	}
	if bundle.SourceDigest != "" {
		// The unchanged digest is the CI-verifiable proof that the legacy Agent
		// source was not touched while the adapter bundle was generated.
		// 未变化的摘要即"生成适配包期间未改动存量 Agent 源码"的可被 CI 校验的证据。
		data["source_digest"] = bundle.SourceDigest
	}
	return result{OK: true, Command: "generate-adapter", Data: data}, 0
}
func packageAgent(args []string, dryRun bool) (result, int) {
	f := flag.NewFlagSet("package", flag.ContinueOnError)
	root := f.String("path", ".", "path")
	sbom := f.String("sbom", "", "optional SPDX JSON output (relative path)")
	image := f.String("image", "", "optional Docker image reference; builds and records a digest")
	provenance := f.String("provenance", "", "optional SLSA provenance JSON output (relative path)")
	if f.Parse(args) != nil {
		return result{Command: "package"}, 2
	}
	// A dry run computes the real content hash but writes neither the SBOM nor
	// the provenance, and validates the image build plan without invoking Docker.
	// dry-run 计算真实内容哈希，但不写 SBOM/provenance，也不调用 Docker，只校验镜像构建计划。
	packageOutput := *sbom
	if dryRun {
		packageOutput = ""
	}
	packaged, err := agentbuild.Package(*root, packageOutput)
	if err != nil {
		return fail("package", "READ_FAILED", err.Error()), 1
	}
	if dryRun {
		data := map[string]any{"dry_run": true, "would_change": true, "root": *root, "content_hash": packaged.ContentHash, "file_count": packaged.FileCount}
		if *image != "" {
			if planErr := agentbuild.PlanImage(*root, *image); planErr != nil {
				return fail("package", "IMAGE_BUILD_FAILED", planErr.Error()), 1
			}
			data["image"] = *image
		}
		if *sbom != "" {
			data["sbom_path"] = *sbom
		}
		if *provenance != "" {
			data["provenance_path"] = *provenance
		}
		return result{OK: true, Command: "package", Data: data}, 0
	}
	if *image != "" {
		built, buildErr := agentbuild.BuildImage(context.Background(), *root, *image, packaged.ContentHash, *provenance)
		if buildErr != nil {
			return fail("package", "IMAGE_BUILD_FAILED", buildErr.Error()), 1
		}
		packaged.Image, packaged.ImageDigest, packaged.Provenance = built.Image, built.ImageDigest, built.Provenance
	}
	return result{OK: true, Command: "package", Data: packaged}, 0
}

func testAgent(args []string) (result, int) {
	f := flag.NewFlagSet("test", flag.ContinueOnError)
	root := f.String("path", ".", "agent bundle path")
	baseURL := f.String("base-url", os.Getenv("CONFORMANCE_BASE_URL"), "running Agent base URL")
	runner := f.String("runner", os.Getenv("CONFORMANCE_RUNNER"), "conformance/runner/run.py path")
	fixture := f.String("lifecycle-fixture", "", "optional gateway-signed lifecycle fixture")
	python := f.String("python", os.Getenv("PYTHON_BIN"), "Python executable")
	if f.Parse(args) != nil {
		return result{Command: "test"}, 2
	}
	if strings.TrimSpace(*baseURL) == "" {
		return fail("test", "BASE_URL_REQUIRED", "--base-url or CONFORMANCE_BASE_URL is required"), 2
	}
	if strings.TrimSpace(*runner) == "" {
		*runner = filepath.Join("conformance", "runner", "run.py")
	}
	if _, err := os.Stat(*runner); err != nil {
		return fail("test", "RUNNER_MISSING", err.Error()), 1
	}
	if strings.TrimSpace(*python) == "" {
		*python = "python"
	}
	if _, code := validate([]string{"--path", *root}); code != 0 {
		return fail("test", "MANIFEST_INVALID", "agent validation failed"), 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	argv := []string{*runner, "--base-url", strings.TrimRight(*baseURL, "/")}
	if strings.TrimSpace(*fixture) != "" {
		argv = append(argv, "--lifecycle-fixture", *fixture)
	}
	cmd := exec.CommandContext(ctx, *python, argv...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if len(message) > 4096 {
			message = message[len(message)-4096:]
		}
		return result{OK: false, Command: "test", Data: map[string]any{"output": message}, Errors: []item{{Code: "CONFORMANCE_FAILED", Message: "Conformance Runner failed"}}}, 1
	}
	var data any
	if json.Unmarshal(output, &data) != nil {
		data = map[string]any{"output": strings.TrimSpace(string(output))}
	}
	return result{OK: true, Command: "test", Data: data}, 0
}

func publish(args []string, dryRun bool) (result, int) {
	f := flag.NewFlagSet("publish", flag.ContinueOnError)
	urlValue := f.String("url", os.Getenv("PLATFORM_PUBLISH_URL"), "exact PF-02 publish API URL")
	token := f.String("token", os.Getenv("PLATFORM_TOKEN"), "platform bearer token")
	root := f.String("path", ".", "agent bundle path")
	revision := f.String("revision", "1", "If-Match revision")
	if f.Parse(args) != nil {
		return result{Command: "publish"}, 2
	}
	if strings.TrimSpace(*urlValue) == "" {
		return fail("publish", "URL_REQUIRED", "--url or PLATFORM_PUBLISH_URL is required; publish never performs a local no-op"), 2
	}
	// A dry run still validates the manifest and computes the exact payload the
	// platform would receive, but it must not require a live credential or send
	// any request. / dry-run 仍校验 manifest 并计算平台将收到的确切载荷，但不要求活动
	// 凭证、也不发送任何请求。
	if !dryRun && strings.TrimSpace(*token) == "" {
		return fail("publish", "TOKEN_REQUIRED", "--token or PLATFORM_TOKEN is required"), 2
	}
	manifestRaw, err := os.ReadFile(filepath.Join(*root, "manifest.json"))
	if err != nil {
		return fail("publish", "MANIFEST_MISSING", err.Error()), 1
	}
	var manifest map[string]any
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		return fail("publish", "MANIFEST_INVALID", err.Error()), 1
	}
	packaged, err := agentbuild.Package(*root, "")
	if err != nil {
		return fail("publish", "PACKAGE_FAILED", err.Error()), 1
	}
	payload := map[string]any{"manifest": manifest, "content_hash": packaged.ContentHash, "status": "draft", "approval_required": true}
	body, _ := json.Marshal(payload)
	if dryRun {
		return result{OK: true, Command: "publish", Data: map[string]any{"dry_run": true, "would_change": true, "url": *urlValue, "agent_id": manifest["agent_id"], "content_hash": packaged.ContentHash, "if_match": *revision, "token_present": strings.TrimSpace(*token) != "", "approval_required": true}}, 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, *urlValue, bytes.NewReader(body))
	if err != nil {
		return fail("publish", "REQUEST_INVALID", err.Error()), 1
	}
	req.Header.Set("Authorization", "Bearer "+*token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", *revision)
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return fail("publish", "GATEWAY_ERROR", err.Error()), 1
	}
	defer resp.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if readErr != nil {
		return fail("publish", "RESPONSE_READ_FAILED", readErr.Error()), 1
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return result{OK: false, Command: "publish", Data: map[string]any{"http_status": resp.StatusCode, "response": string(raw)}, Errors: []item{{Code: "PUBLISH_REJECTED", Message: "platform publish API rejected the draft"}}}, 1
	}
	var response any
	if json.Unmarshal(raw, &response) != nil {
		response = map[string]any{"raw": string(raw)}
	}
	return result{OK: true, Command: "publish", Data: map[string]any{"status": "draft_submitted", "approval_required": true, "response": response, "content_hash": packaged.ContentHash}}, 0
}
func upgrade(args []string) (result, int) {
	f := flag.NewFlagSet("upgrade", flag.ContinueOnError)
	f.SetOutput(os.Stderr)
	workspace := f.String("workspace", "", "agent workspace path")
	path := f.String("path", ".", "agent workspace path (alias for --workspace)")
	version := f.String("to-template-version", "", "target template version")
	templateRoot := f.String("template-root", "", "immutable template registry root")
	registry := f.String("registry", os.Getenv("AGENTCTL_REGISTRY_URL"), "remote immutable template registry base URL")
	registryKey := f.String("registry-key", os.Getenv("AGENTCTL_REGISTRY_KEY_FILE"), "path to the base64 ed25519 registry public key file")
	dryRun := f.Bool("dry-run", false, "calculate changes without writing files")
	// Accepted for direct callers; main() already strips the global --json flag.
	_ = f.Bool("json", false, "emit agentctl-output/v1 JSON (default)")
	if f.Parse(args) != nil {
		return result{Command: "upgrade"}, 2
	}
	target := strings.TrimSpace(*path)
	if strings.TrimSpace(*workspace) != "" {
		target = *workspace
	}
	if strings.TrimSpace(*version) == "" {
		return fail("upgrade", "TEMPLATE_VERSION_REQUIRED", "--to-template-version is required"), 2
	}
	root := strings.TrimSpace(*templateRoot)
	if strings.TrimSpace(*registry) != "" {
		// The remote path reads the workspace identity first, fetches the signed
		// artifact into a verified staging registry and then upgrades exactly
		// like the local path. A dry run still performs the fetch: the plan is
		// only trustworthy if the artifact itself verified.
		// 远端路径先读取工作区身份，把已签名的工件取到通过校验的暂存注册表，再与
		// 本地路径完全一致地升级。dry-run 仍会执行获取：只有工件本身通过校验，
		// 计划才可信。
		if strings.TrimSpace(*registryKey) == "" {
			return fail("upgrade", "REGISTRY_KEY_REQUIRED", "--registry-key or AGENTCTL_REGISTRY_KEY_FILE is required with --registry"), 2
		}
		key, keyErr := agenttemplate.LoadRemoteKey(*registryKey)
		if keyErr != nil {
			code := "REGISTRY_KEY_INVALID"
			var upgradeKeyErr *agenttemplate.UpgradeError
			if errors.As(keyErr, &upgradeKeyErr) {
				code = upgradeKeyErr.Code
			}
			return fail("upgrade", code, keyErr.Error()), 1
		}
		templateID, _, idErr := agenttemplate.WorkspaceIdentity(target)
		if idErr != nil {
			var idUpgradeErr *agenttemplate.UpgradeError
			code := "UPGRADE_FAILED"
			if errors.As(idErr, &idUpgradeErr) {
				code = idUpgradeErr.Code
			}
			return fail("upgrade", code, idErr.Error()), 1
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		staging, cleanup, fetchErr := agenttemplate.FetchTemplate(ctx, agenttemplate.FetchOptions{
			BaseURL: strings.TrimSpace(*registry), PublicKey: key,
		}, templateID, strings.TrimSpace(*version))
		if fetchErr != nil {
			var fetchUpgradeErr *agenttemplate.UpgradeError
			code := "REGISTRY_FETCH_FAILED"
			if errors.As(fetchErr, &fetchUpgradeErr) {
				code = fetchUpgradeErr.Code
			}
			return fail("upgrade", code, fetchErr.Error()), 1
		}
		defer cleanup()
		root = staging
	}
	report, err := agenttemplate.Upgrade(agenttemplate.UpgradeOptions{
		Workspace: target, TemplateRoot: root, ToVersion: *version, DryRun: *dryRun,
	})
	if err == nil {
		return result{OK: true, Command: "upgrade", Data: report}, 0
	}
	var upgradeErr *agenttemplate.UpgradeError
	code := "UPGRADE_FAILED"
	if errors.As(err, &upgradeErr) {
		code = upgradeErr.Code
	}
	data := any(nil)
	if report.Workspace != "" || report.Status != "" {
		data = report
	}
	return result{OK: false, Command: "upgrade", Data: data, Errors: []item{{Code: code, Message: err.Error()}}}, 1
}
func writeJSON(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0644)
}
func fail(cmd, code, msg string) result {
	return result{OK: false, Command: cmd, Errors: []item{{Code: code, Message: msg}}}
}
