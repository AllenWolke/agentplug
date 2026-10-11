package inspect

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const maxFileBytes = 8 << 20

// Run walks only regular files and records every read failure. A report with a
// read error is failed by callers, because an incomplete inventory is unsafe.
// Run 只读取普通文件并记录全部错误；不完整的盘点不可用于自动接入。
func Run(root string) (Report, error) {
	started := time.Now().UTC()
	report := Report{InventoryVersion: "agent-inventory/v1", Root: root, Files: []string{}, Findings: []Finding{}, StartedAt: started}
	info, err := os.Stat(root)
	if err != nil {
		return report, err
	}
	if !info.IsDir() {
		return report, errors.New("inspection root must be a directory")
	}
	var contents [][]byte
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			report.ReadErrors = append(report.ReadErrors, path+": "+walkErr.Error())
			return nil
		}
		if entry.IsDir() {
			if path != root && skipDir(entry.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		relative, relErr := filepath.Rel(root, path)
		if relErr != nil {
			report.ReadErrors = append(report.ReadErrors, path+": "+relErr.Error())
			return nil
		}
		rel := filepath.ToSlash(relative)
		if entry.Type()&fs.ModeSymlink != 0 {
			report.Skipped = append(report.Skipped, rel+": symlink")
			return nil
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			report.ReadErrors = append(report.ReadErrors, path+": "+infoErr.Error())
			return nil
		}
		if shouldSkipFile(entry.Name(), info.Size()) {
			report.Skipped = append(report.Skipped, rel)
			return nil
		}
		report.Files = append(report.Files, rel)
		file, openErr := os.Open(path)
		if openErr != nil {
			report.ReadErrors = append(report.ReadErrors, path+": "+openErr.Error())
			return nil
		}
		data, readErr := readBounded(file, maxFileBytes)
		closeErr := file.Close()
		if readErr != nil {
			report.ReadErrors = append(report.ReadErrors, path+": "+readErr.Error())
			return nil
		}
		if closeErr != nil {
			report.ReadErrors = append(report.ReadErrors, path+": "+closeErr.Error())
			return nil
		}
		contents = append(contents, data)
		return nil
	})
	if err != nil {
		return report, err
	}
	sort.Strings(report.Files)
	sort.Strings(report.Skipped)
	joined := bytes.Join(contents, []byte("\n"))
	report.Language, report.Framework = detectLanguage(report.Files, joined)
	report.AgentID = detectAgentID(root, joined)
	report.Findings = findings(report.Files, joined)
	for _, finding := range report.Findings {
		if finding.ID == "transport" {
			if finding.Status == Confirmed {
				report.SuggestedAdapter = "legacy-http"
			}
		}
	}
	report.FinishedAt = time.Now().UTC()
	if len(report.ReadErrors) > 0 {
		return report, fmt.Errorf("inspection incomplete: %d read errors", len(report.ReadErrors))
	}
	return report, nil
}

func skipDir(name string) bool {
	// Build outputs, dependency caches and tool state are never Agent source;
	// inspecting them produces noise and, worse, can make an inventory fail on a
	// compiled binary that exceeds the read limit.
	// 构建产物、依赖缓存与工具状态都不是 Agent 源码；盘点它们只会产生噪声，甚至因编译
	// 产物超过读取上限而让整次盘点失败。
	switch name {
	case ".git", ".venv", "venv", "node_modules", "__pycache__", "tmp", ".tmp",
		"target", "build", "dist", "out", "bin", "obj", "coverage",
		".gradle", ".mvn", ".idea", ".vscode", ".pytest_cache", ".mypy_cache",
		".ruff_cache", ".cache", "chroma_db", ".zread":
		return true
	}
	return strings.HasPrefix(name, ".tmp")
}

// skippedExtensions lists compiled artifacts, archives, media and embedded
// databases that carry no inspectable Agent structure.
// skippedExtensions 列出编译产物、归档、媒体与嵌入式数据库等无可盘点结构的文件。
var skippedExtensions = map[string]bool{
	".exe": true, ".dll": true, ".so": true, ".dylib": true, ".a": true, ".o": true, ".obj": true,
	".lib": true, ".pdb": true, ".jar": true, ".class": true, ".war": true, ".ear": true,
	".pyc": true, ".pyo": true, ".whl": true, ".egg": true,
	".zip": true, ".tar": true, ".gz": true, ".tgz": true, ".bz2": true, ".xz": true, ".7z": true, ".rar": true,
	".bin": true, ".db": true, ".sqlite": true, ".sqlite3": true,
	".mp3": true, ".wav": true, ".m4a": true, ".flac": true, ".ogg": true, ".mp4": true, ".mov": true, ".avi": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".bmp": true, ".ico": true, ".webp": true,
	".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true, ".ppt": true, ".pptx": true,
	".ttf": true, ".otf": true, ".woff": true, ".woff2": true, ".eot": true, ".wasm": true,
}

// shouldSkipFile reports whether a regular file is source or an artifact. Files
// larger than the read limit are treated as artifacts rather than read errors so
// a real inventory cannot be defeated by one committed binary.
// shouldSkipFile 判断普通文件是源码还是产物。超过读取上限的文件按产物处理而非读取错误，
// 使真实盘点不会因仓库里的一个二进制而失败。
func shouldSkipFile(name string, size int64) bool {
	if size > maxFileBytes {
		return true
	}
	return skippedExtensions[strings.ToLower(filepath.Ext(name))]
}
func readBounded(file *os.File, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("file exceeds inspection limit")
	}
	return data, nil
}
func detectLanguage(files []string, data []byte) (string, string) {
	var py, goCount, java, js int
	for _, name := range files {
		switch filepath.Ext(name) {
		case ".py":
			py++
		case ".go":
			goCount++
		case ".java":
			java++
		case ".js", ".ts", ".tsx", ".jsx":
			js++
		}
	}
	lower := bytes.ToLower(data)
	has := func(marker string) bool { return bytes.Contains(lower, []byte(marker)) }
	switch {
	case py > 0:
		for _, framework := range []string{"langgraph", "django", "streamlit", "flask", "fastapi"} {
			if has(framework) {
				return "python", framework
			}
		}
		return "python", "unknown"
	case goCount > 0:
		for _, framework := range []string{"eino", "gin-gonic/gin", "fiber", "grpc"} {
			if has(framework) {
				return "go", framework
			}
		}
		return "go", "unknown"
	case java > 0:
		for _, framework := range []string{"spring-ai", "spring", "quarkus", "micronaut"} {
			if has(framework) {
				return "java", framework
			}
		}
		return "java", "unknown"
	case js > 0:
		for _, framework := range []string{"next", "nestjs", "express", "fastify", "react"} {
			if has(framework) {
				return "node", framework
			}
		}
		return "node", "unknown"
	default:
		return "unknown", "unknown"
	}
}

var agentIDPattern = regexp.MustCompile(`(?m)(?:agent_id|AGENT_ID|name)\s*[:=]\s*["']?([a-zA-Z][a-zA-Z0-9_-]{2,63})`)

func detectAgentID(root string, data []byte) string {
	if match := agentIDPattern.FindSubmatch(data); len(match) > 1 {
		return strings.ToLower(string(match[1]))
	}
	return filepath.Base(root)
}
func findings(files []string, data []byte) []Finding {
	text := strings.ToLower(string(data))
	found := func(pattern string) bool { return strings.Contains(text, pattern) }
	anyFound := func(patterns []string) bool {
		for _, pattern := range patterns {
			if found(pattern) {
				return true
			}
		}
		return false
	}
	transport := Finding{ID: "transport", Status: Unknown, Summary: "no supported Agent transport detected", Confidence: .2}
	// HTTP is checked first: a legacy Agent that exposes an HTTP API is adapted
	// through legacy-http even when it also mentions MCP, gRPC or a queue.
	// 先判定 HTTP：只要存量 Agent 暴露 HTTP API，即使同时提及 MCP/gRPC/队列，也按
	// legacy-http 适配。
	switch {
	case anyFound([]string{"fastapi", "flask", "django", "uvicorn", "starlette", "streamlit", "gradio",
		"gin-gonic/gin", "gin.default()", "gin.new()", "http.handlefunc", "http.listenandserve",
		"net/http", "servemux", "@restcontroller", "@requestmapping", "@postmapping", "@getmapping",
		"httpservlet", "express()", "fastify", "@nestjs"}):
		transport = Finding{ID: "transport", Status: Confirmed, Summary: "HTTP entry point detected", Confidence: .95}
	case found("grpc"):
		transport = Finding{ID: "transport", Status: Confirmed, Summary: "gRPC entry point detected", Confidence: .9}
	case anyFound([]string{"modelcontextprotocol", "mcp.server", "mcp_server", "@modelcontextprotocol"}):
		transport = Finding{ID: "transport", Status: Confirmed, Summary: "MCP server entry point detected", Confidence: .8}
	case anyFound([]string{"celery", "kombu", "confluent_kafka", "kafka-python", "amqp", "rabbitmq", "aws sqs"}):
		transport = Finding{ID: "transport", Status: Confirmed, Summary: "queue consumer entry point detected", Confidence: .7}
	case anyFound([]string{"argparse", "click.command", "typer", "cobra.command", "urfave/cli"}):
		transport = Finding{ID: "transport", Status: Confirmed, Summary: "CLI entry point detected", Confidence: .7}
	}
	state := Finding{ID: "state", Status: Unknown, Summary: "runtime state storage is unknown", Confidence: .2}
	if anyFound([]string{"memorystore", "memorysaver", "session_state", "st.session_state", "global ",
		"chromadb", "chroma_db", "faiss", "pinecone", "neo4j", "sqlite", "local-lexagent.db"}) {
		state = Finding{ID: "state", Status: Confirmed, Summary: "process-local or embedded state store detected; externalize before scale-out", Confidence: .8}
	}
	secrets := Finding{ID: "secrets", Status: Confirmed, Summary: "no obvious credential literal detected", Confidence: .6}
	if anyFound([]string{"api_key=", "app_secret", "password=", "authorization: bearer", "secret_key", "localhost", "127.0.0.1", "sk-"}) {
		secrets = Finding{ID: "secrets", Status: Confirmed, Summary: "possible hard-coded credential, loopback endpoint or bearer forwarding detected", Confidence: .9}
	}
	build := Finding{ID: "build", Status: Unknown, Summary: "build metadata is incomplete", Confidence: .2}
	for _, file := range files {
		base := strings.ToLower(filepath.Base(file))
		if base == "dockerfile" || strings.HasSuffix(file, "go.mod") || strings.HasSuffix(file, "requirements.txt") ||
			strings.HasSuffix(file, "pom.xml") || strings.HasSuffix(file, "build.gradle") ||
			strings.HasSuffix(file, "package.json") || strings.HasSuffix(file, "pyproject.toml") {
			build = Finding{ID: "build", Status: Confirmed, Summary: "build/dependency metadata detected", Evidence: []string{file}, Confidence: .9}
			break
		}
	}
	return []Finding{transport, state, secrets, build}
}

func Encode(report Report) ([]byte, error) { return json.MarshalIndent(report, "", "  ") }
