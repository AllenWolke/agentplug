// prepare-code-runtime provisions independent local operator material. It never
// starts Docker, publishes IAM/Tool policies, approves tools or changes a DB.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	protocol "github.com/lexagent/code-runtime-contract"
)

type options struct {
	directory, ip, subnet, tenant, application string
	python, javascript, shell                  string
	dockerCLI, socketGID                       string
}

func main() {
	var o options
	flag.StringVar(&o.directory, "output", "", "new private directory under .local-secrets; never overwritten")
	flag.StringVar(&o.ip, "private-ip", "", "explicit IPv4 controller address")
	flag.StringVar(&o.subnet, "subnet", "", "dedicated private Compose subnet containing the controller")
	flag.StringVar(&o.tenant, "tenant", "", "actual example tenant")
	flag.StringVar(&o.application, "application", "", "actual example application")
	flag.StringVar(&o.python, "python-image-id", "", "existing immutable Docker image ID")
	flag.StringVar(&o.javascript, "javascript-image-id", "", "existing immutable Docker image ID")
	flag.StringVar(&o.shell, "shell-image-id", "", "existing immutable Docker image ID")
	flag.StringVar(&o.dockerCLI, "docker-cli-image", "", "verified docker.io/library/docker@sha256 digest; requires socket-gid")
	flag.StringVar(&o.socketGID, "socket-gid", "", "verified Docker Engine socket numeric group; requires docker-cli-image")
	flag.Parse()
	if err := prepare(o); err != nil {
		fmt.Fprintln(os.Stderr, "Code runtime preparation failed:", err)
		os.Exit(1)
	}
	fmt.Println("Private Code runtime material prepared; no service started, policy published or permission granted.")
}

func encodeKey(key []byte) []byte { return []byte(base64.StdEncoding.EncodeToString(key) + "\n") }

func jsonFile(value any) ([]byte, error) {
	body, err := json.MarshalIndent(value, "", "  ")
	return append(body, '\n'), err
}

func prepare(o options) error {
	address, err := netip.ParseAddr(o.ip)
	subnet, subnetErr := netip.ParsePrefix(o.subnet)
	id := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$`)
	imageID := regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	if err != nil || subnetErr != nil || !address.Is4() || !address.IsPrivate() ||
		!subnet.Addr().Is4() || !subnet.Addr().IsPrivate() || subnet != subnet.Masked() ||
		subnet.Bits() < 16 || subnet.Bits() > 28 || !subnet.Contains(address) ||
		address == subnet.Addr() || !id.MatchString(o.tenant) || !id.MatchString(o.application) {
		return errors.New("explicit valid private address/subnet and scope required")
	}
	networkBytes, addressBytes := subnet.Addr().As4(), address.As4()
	broadcast := binary.BigEndian.Uint32(networkBytes[:]) | (^uint32(0) >> uint(subnet.Bits()))
	if address == subnet.Addr().Next() || binary.BigEndian.Uint32(addressBytes[:]) == broadcast {
		return errors.New("controller address cannot be the default gateway or broadcast")
	}
	platformAddress, err := choosePlatformPrivateIP(subnet, address)
	if err != nil {
		return err
	}
	for _, image := range []string{o.python, o.javascript, o.shell} {
		if !imageID.MatchString(image) {
			return errors.New("three actual immutable image IDs required")
		}
	}
	if (o.dockerCLI == "") != (o.socketGID == "") {
		return errors.New("Docker CLI digest and verified socket group must be supplied together")
	}
	if o.dockerCLI != "" {
		if !regexp.MustCompile(`^docker\.io/library/docker@sha256:[0-9a-f]{64}$`).MatchString(o.dockerCLI) ||
			!regexp.MustCompile(`^(0|[1-9][0-9]{0,9})$`).MatchString(o.socketGID) {
			return errors.New("immutable official Docker CLI digest and numeric socket group required")
		}
		if _, err := strconv.ParseUint(o.socketGID, 10, 32); err != nil {
			return errors.New("socket group exceeds the supported numeric range")
		}
	}
	root, err := filepath.Abs(o.directory)
	if err != nil || o.directory == "" || !hasPrivateComponent(root) {
		return errors.New("output must be under a .local-secrets directory")
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		return errors.New("output already exists or cannot be verified; never replace receipt keys")
	}
	resolvedParent, err := filepath.EvalSymlinks(filepath.Dir(root))
	if err != nil || !hasPrivateComponent(resolvedParent) {
		return errors.New("private parent must already exist and resolve under .local-secrets")
	}
	_, permitKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return errors.New("key generation failed")
	}
	defer clear(permitKey)
	_, approvalKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return errors.New("key generation failed")
	}
	defer clear(approvalKey)
	stateKey := make([]byte, 32)
	if _, err = rand.Read(stateKey); err != nil {
		return errors.New("key generation failed")
	}
	defer clear(stateKey)
	caPublic, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return errors.New("TLS generation failed")
	}
	defer clear(caKey)
	serverPublic, serverKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return errors.New("TLS generation failed")
	}
	defer clear(serverKey)
	serial := func() (*big.Int, error) { return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128)) }
	caSerial, err := serial()
	if err != nil {
		return errors.New("TLS generation failed")
	}
	serverSerial, err := serial()
	if err != nil {
		return errors.New("TLS generation failed")
	}
	now := time.Now().UTC()
	ca := &x509.Certificate{SerialNumber: caSerial, Subject: pkix.Name{CommonName: "agentplug local code controller CA"},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(1, 0, 0), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caPublic, caKey)
	if err != nil {
		return errors.New("TLS generation failed")
	}
	certificate := &x509.Certificate{SerialNumber: serverSerial, Subject: pkix.Name{CommonName: "agentplug-code-controller"},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(1, 0, 0),
		IPAddresses: []net.IP{net.IP(address.AsSlice())}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	serverDER, err := x509.CreateCertificate(rand.Reader, certificate, ca, serverPublic, caKey)
	if err != nil {
		return errors.New("TLS generation failed")
	}
	serverPrivate, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		return errors.New("TLS generation failed")
	}
	defer clear(serverPrivate)
	var ownerNonce [12]byte
	if _, err = rand.Read(ownerNonce[:]); err != nil {
		return errors.New("owner generation failed")
	}
	limits := protocol.Limits{MemoryBytes: 128 << 20, CPUMilli: 500, CPUSeconds: 5,
		PIDs: 16, DiskBytes: 8 << 20, TimeoutSeconds: 15, OutputBytes: 64 << 10}
	if limits.Validate() != nil {
		return errors.New("execution limits invalid")
	}
	profiles, bindings := []any{}, []any{}
	for _, language := range []string{"python", "javascript", "shell"} {
		tool, profile := "code."+language, "example-"+language+"-v1"
		profiles = append(profiles, map[string]any{"id": profile, "tool_name": tool, "language": language, "limits": limits})
		bindings = append(bindings, map[string]any{"tool_name": tool, "profile_id": profile, "controller_id": "agentplug-code-controller",
			"language": language, "limits": limits, "endpoint": "https://" + address.String() + ":8443", "tenant_id": o.tenant,
			"application_id": o.application, "agent_ids": []string{"example-go-operations", "example-python-documents", "example-java-tickets"}})
	}
	config := map[string]any{"listen_address": address.String() + ":8443", "controller_id": "agentplug-code-controller",
		"public_key_file": "/etc/agentplug-code/permit-public.key", "state_key_file": "/etc/agentplug-code/controller-state.key",
		"tls_certificate_file": "/etc/agentplug-code/controller.crt", "tls_private_key_file": "/etc/agentplug-code/controller.key",
		"state_directory": "/var/lib/agentplug-code/receipts", "docker_config_directory": "/var/lib/agentplug-code/docker",
		"owner": "agentplug-code-" + hex.EncodeToString(ownerNonce[:]), "images": map[string]string{"python": o.python, "javascript": o.javascript, "shell": o.shell},
		"profiles": profiles, "max_concurrent": 2}
	configJSON, err := jsonFile(config)
	if err != nil {
		return errors.New("configuration encoding failed")
	}
	bindingsJSON, err := jsonFile(bindings)
	if err != nil {
		return errors.New("configuration encoding failed")
	}
	files := map[string][]byte{"platform-permit.key": encodeKey(permitKey), "permit-public.key": encodeKey(permitKey.Public().(ed25519.PublicKey)),
		"tool-approval.key": encodeKey(approvalKey), "controller-state.key": encodeKey(stateKey),
		"controller-ca.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		"controller.crt":    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}),
		"controller.key":    pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverPrivate}),
		"code-runtime.json": configJSON, "bindings.json": bindingsJSON,
		"compose.env": []byte("CODE_RUNTIME_PRIVATE_IP=" + address.String() + "\nCODE_RUNTIME_PLATFORM_PRIVATE_IP=" + platformAddress.String() + "\nCODE_RUNTIME_SUBNET=" + subnet.String() + "\n")}
	if o.dockerCLI != "" {
		files["compose.env"] = append(files["compose.env"], []byte("CODE_RUNTIME_DOCKER_CLI_IMAGE="+o.dockerCLI+"\nCODE_RUNTIME_DOCKER_SOCKET_GID="+o.socketGID+"\n")...)
	}
	defer func() {
		for _, body := range files {
			clear(body)
		}
	}()
	// Parents must already be provisioned by the operator. A new directory and
	// exclusive files prevent overwriting an active controller's receipt keys.
	if err = os.Mkdir(root, 0700); err != nil {
		return errors.New("new private output directory unavailable")
	}
	for name, body := range files {
		f, err := os.OpenFile(filepath.Join(root, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return errors.New("private preparation incomplete; preserve directory for operator inspection")
		}
		_, writeErr := f.Write(body)
		closeErr := f.Close()
		if writeErr != nil || closeErr != nil {
			return errors.New("private preparation incomplete; preserve directory for operator inspection")
		}
	}
	return nil
}

// choosePlatformPrivateIP returns a second usable address for platform-app on
// the dedicated controller subnet. The first host is the Docker gateway; the
// controller address is skipped, then the lowest remaining usable host wins.
func choosePlatformPrivateIP(subnet netip.Prefix, controller netip.Addr) (netip.Addr, error) {
	if !subnet.IsValid() || !subnet.Addr().Is4() || subnet != subnet.Masked() ||
		subnet.Bits() < 16 || subnet.Bits() > 28 || !subnet.Addr().IsPrivate() ||
		!controller.Is4() || !controller.IsPrivate() || !subnet.Contains(controller) {
		return netip.Addr{}, errors.New("valid dedicated private IPv4 subnet and controller address required")
	}
	networkBytes := subnet.Addr().As4()
	networkValue := binary.BigEndian.Uint32(networkBytes[:])
	broadcastValue := networkValue | (^uint32(0) >> uint(subnet.Bits()))
	var broadcastBytes [4]byte
	binary.BigEndian.PutUint32(broadcastBytes[:], broadcastValue)
	broadcast := netip.AddrFrom4(broadcastBytes)
	gateway := subnet.Addr().Next()
	if controller == subnet.Addr() || controller == gateway || controller == broadcast {
		return netip.Addr{}, errors.New("controller address conflicts with network, gateway, or broadcast")
	}
	for candidate := gateway.Next(); subnet.Contains(candidate) && candidate != broadcast; candidate = candidate.Next() {
		if candidate != controller {
			return candidate, nil
		}
	}
	return netip.Addr{}, errors.New("dedicated private IPv4 subnet has no second usable platform address")
}

func hasPrivateComponent(path string) bool {
	for _, part := range strings.FieldsFunc(path, func(r rune) bool { return r == '/' || r == '\\' }) {
		if part == ".local-secrets" {
			return true
		}
	}
	return false
}
