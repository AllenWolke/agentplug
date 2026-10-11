// Command plugin-registry signs and installs pre-built metric plugin artifacts
// into an operator-owned registry. Registration is the only step that may turn
// a binary into a runnable plugin, and it does so through the frozen descriptor
// contract: the tool computes the artifact digest, pins it in the descriptor,
// signs the descriptor with a freshly generated Ed25519 key and writes the
// matching public key next to the registry. The private key is never persisted,
// so a run can be verified but never re-signed from the registry contents.
// Command plugin-registry 把预构建的指标插件制品签名并安装进运维护有的注册表。登记是唯一能把
// 一个二进制变成可运行插件的步骤，并严格经由冻结的描述符契约完成：工具计算制品摘要、把它固定进
// 描述符、用新生成的 Ed25519 密钥签名描述符，并把对应公钥写在注册表旁边。私钥绝不落盘，因此
// 一次运行可被校验，却无法由注册表内容重新签名。
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/lexagent/metric-runner/internal/protocol"
)

// publicKeyFile is where the freshly generated verification key is published.
// The runner's operator configuration points at exactly this file, so the key
// and the descriptors it signed can never drift apart.
// publicKeyFile 是新生成的校验公钥的发布位置。Runner 的运维配置正指向该文件，使密钥与其签名
// 的描述符不可能相互漂移。
const publicKeyFile = "public.key"

type spec struct {
	Root    string       `json:"root"`
	Plugins []pluginSpec `json:"plugins"`
}

type pluginSpec struct {
	ID       string          `json:"id"`
	Version  string          `json:"version"`
	Artifact string          `json:"artifact"`
	Args     []string        `json:"args"`
	Limits   protocol.Limits `json:"limits"`
}

func main() {
	root := flag.String("root", "/plugins", "registry root; also the runtime entrypoint prefix")
	specPath := flag.String("spec", "", "path to the registry spec JSON document")
	flag.Parse()
	if err := run(*root, *specPath, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "plugin-registry:", err)
		os.Exit(1)
	}
}

func run(root, specPath string, out *os.File) error {
	if strings.TrimSpace(specPath) == "" {
		return errors.New("registry spec is required")
	}
	raw, err := os.ReadFile(specPath)
	if err != nil {
		return fmt.Errorf("read registry spec: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var s spec
	if err := dec.Decode(&s); err != nil {
		return fmt.Errorf("decode registry spec: %w", err)
	}
	if trimmed := strings.TrimSpace(s.Root); trimmed != "" {
		root = trimmed
	}
	if len(s.Plugins) == 0 {
		return errors.New("registry spec lists no plugins")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate signing key: %w", err)
	}
	for _, plugin := range s.Plugins {
		installed, err := install(root, plugin, private)
		if err != nil {
			return fmt.Errorf("register %s: %w", plugin.ID, err)
		}
		fmt.Fprintf(out, "registered %s -> %s\n", plugin.ID, installed)
	}
	keyPath := filepath.Join(root, publicKeyFile)
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(public)), 0o644); err != nil {
		return fmt.Errorf("publish public key: %w", err)
	}
	fmt.Fprintf(out, "published public key -> %s\n", keyPath)
	return nil
}

// install copies one artifact into its registry entry, pins its digest in a
// signed descriptor and returns the entrypoint it registered. The entrypoint is
// derived from the runtime root, not from the build location, so the descriptor
// stays valid after the registry is mounted at its final path.
// install 把一个制品复制进其注册项，把摘要固定进已签名描述符，并返回登记入口。入口由运行时根
// 推导而非构建位置，因此注册表挂载到最终路径后描述符依然有效。
func install(root string, plugin pluginSpec, key ed25519.PrivateKey) (string, error) {
	if strings.TrimSpace(plugin.ID) == "" || strings.TrimSpace(plugin.Artifact) == "" {
		return "", errors.New("plugin id and artifact are required")
	}
	payload, err := os.ReadFile(plugin.Artifact)
	if err != nil {
		return "", fmt.Errorf("read artifact: %w", err)
	}
	dir := filepath.Join(root, plugin.ID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create registry entry: %w", err)
	}
	name := filepath.Base(plugin.Artifact)
	if err := os.WriteFile(filepath.Join(dir, name), payload, 0o755); err != nil {
		return "", fmt.Errorf("install artifact: %w", err)
	}
	descriptor := protocol.Descriptor{
		ID:         plugin.ID,
		Version:    plugin.Version,
		Entrypoint: filepath.Join(root, plugin.ID, name),
		SHA256:     protocol.DigestOf(payload),
		Args:       plugin.Args,
		Network:    protocol.NetworkNone,
		Limits:     plugin.Limits,
	}
	descriptor.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, descriptor.CanonicalBytes()))
	if err := descriptor.Validate(); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(descriptor)
	if err != nil {
		return "", fmt.Errorf("encode descriptor: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "plugin.json"), encoded, 0o644); err != nil {
		return "", fmt.Errorf("write descriptor: %w", err)
	}
	return descriptor.Entrypoint, nil
}
