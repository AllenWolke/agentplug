package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testPKI issues a throwaway CA plus a server and a client certificate so the
// mutual-TLS behaviour can be exercised against a real TLS handshake.
// testPKI 签发一次性 CA 以及服务端、客户端证书，使双向 TLS 行为能在真实 TLS
// 握手上演练。
type testPKI struct {
	serverCertificate tls.Certificate
	clientCertPEM     []byte
	clientKeyPEM      []byte
	caPEM             []byte
	clientCAs         *x509.CertPool
}

func newTestPKI(t *testing.T) testPKI {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "sidecar-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(caCertificate)

	issue := func(serial int64, commonName string, usage x509.ExtKeyUsage, ipAddresses []net.IP) (tls.Certificate, []byte, []byte) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: commonName},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{usage},
			IPAddresses:  ipAddresses,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, caCertificate, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key, Leaf: leaf}, certPEM, keyPEM
	}

	serverCertificate, _, _ := issue(2, "sidecar-test-server", x509.ExtKeyUsageServerAuth, []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback})
	_, clientCertPEM, clientKeyPEM := issue(3, "sidecar-test-client", x509.ExtKeyUsageClientAuth, nil)
	return testPKI{serverCertificate: serverCertificate, clientCertPEM: clientCertPEM, clientKeyPEM: clientKeyPEM, caPEM: caPEM, clientCAs: clientCAs}
}

func (p testPKI) writeFiles(t *testing.T) TLSFiles {
	t.Helper()
	dir := t.TempDir()
	certFile := filepath.Join(dir, "client.crt")
	keyFile := filepath.Join(dir, "client.key")
	caFile := filepath.Join(dir, "ca.crt")
	for path, data := range map[string][]byte{certFile: p.clientCertPEM, keyFile: p.clientKeyPEM, caFile: p.caPEM} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return TLSFiles{ClientCertFile: certFile, ClientKeyFile: keyFile, ServerCAFile: caFile}
}

// TestMutualTLSHandshakeSucceedsWithRegisteredClientIdentity proves the sidecar
// presents its own certificate: the upstream is configured to require and
// verify a client certificate, so the call could not succeed otherwise.
// TestMutualTLSHandshakeSucceedsWithRegisteredClientIdentity 证明 Sidecar 确实出示
// 自身证书：上游被配置为强制校验客户端证书，否则调用不可能成功。
func TestMutualTLSHandshakeSucceedsWithRegisteredClientIdentity(t *testing.T) {
	pki := newTestPKI(t)
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"protocol_version":"agent-execution/v2","run_id":"run-1","status":"succeeded"}`))
	}))
	upstream.TLS = &tls.Config{
		Certificates: []tls.Certificate{pki.serverCertificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pki.clientCAs,
		MinVersion:   tls.VersionTLS12,
	}
	upstream.StartTLS()
	defer upstream.Close()

	client, err := NewMutualTLSClient(pki.writeFiles(t), 5*time.Second)
	if err != nil {
		t.Fatalf("NewMutualTLSClient() error = %v", err)
	}
	response, err := (Proxy{BaseURL: upstream.URL, Client: client}).Invoke(context.Background(), validRequest())
	if err != nil {
		t.Fatalf("mutual TLS invoke failed: %v", err)
	}
	if response.RunID != "run-1" || response.Status != "succeeded" {
		t.Fatalf("unexpected response: %+v", response)
	}
}

// TestUpstreamRejectsCallerWithoutClientCertificate is the negative half: a
// client that presents no certificate cannot complete the handshake against the
// same upstream, which is what makes the positive case meaningful.
// TestUpstreamRejectsCallerWithoutClientCertificate 是反向用例：不出示客户端证书的
// 调用方无法与同一上游完成握手，这才使正向用例具备意义。
func TestUpstreamRejectsCallerWithoutClientCertificate(t *testing.T) {
	pki := newTestPKI(t)
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	upstream.TLS = &tls.Config{
		Certificates: []tls.Certificate{pki.serverCertificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pki.clientCAs,
		MinVersion:   tls.VersionTLS12,
	}
	upstream.StartTLS()
	defer upstream.Close()

	anonymous := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}}
	if _, err := (Proxy{BaseURL: upstream.URL, Client: anonymous}).Invoke(context.Background(), validRequest()); err == nil {
		t.Fatal("an anonymous client completed a mutual-TLS handshake")
	}
}

// TestMutualTLSClientRefusesIncompleteOrUntrustedConfiguration proves the
// client fails closed instead of silently degrading to unauthenticated TLS.
// TestMutualTLSClientRefusesIncompleteOrUntrustedConfiguration 证明客户端失败闭合，
// 不会静默降级成未认证的 TLS。
func TestMutualTLSClientRefusesIncompleteOrUntrustedConfiguration(t *testing.T) {
	pki := newTestPKI(t)
	files := pki.writeFiles(t)

	if _, err := NewMutualTLSClient(TLSFiles{ServerCAFile: files.ServerCAFile}, time.Second); !errors.Is(err, ErrTLSConfigInvalid) {
		t.Fatalf("missing client certificate was accepted: %v", err)
	}
	if _, err := NewMutualTLSClient(TLSFiles{ClientCertFile: files.ClientCertFile, ClientKeyFile: filepath.Join(t.TempDir(), "missing.key")}, time.Second); !errors.Is(err, ErrTLSConfigInvalid) {
		t.Fatalf("missing client key was accepted: %v", err)
	}
	badCA := filepath.Join(t.TempDir(), "bad-ca.crt")
	if err := os.WriteFile(badCA, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewMutualTLSClient(TLSFiles{ClientCertFile: files.ClientCertFile, ClientKeyFile: files.ClientKeyFile, ServerCAFile: badCA}, time.Second); !errors.Is(err, ErrTLSConfigInvalid) {
		t.Fatalf("empty CA bundle was accepted: %v", err)
	}
}

// TestServerVerificationIsNeverDisabled proves the client does validate the
// upstream certificate: pinning an unrelated CA makes the call fail.
// TestServerVerificationIsNeverDisabled 证明客户端确实校验上游证书：固定一个无关 CA
// 会让调用失败。
func TestServerVerificationIsNeverDisabled(t *testing.T) {
	pki := newTestPKI(t)
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	upstream.TLS = &tls.Config{Certificates: []tls.Certificate{pki.serverCertificate}, MinVersion: tls.VersionTLS12}
	upstream.StartTLS()
	defer upstream.Close()

	otherPKI := newTestPKI(t)
	files := pki.writeFiles(t)
	files.ServerCAFile = otherPKI.writeFiles(t).ServerCAFile
	client, err := NewMutualTLSClient(files, 5*time.Second)
	if err != nil {
		t.Fatalf("NewMutualTLSClient() error = %v", err)
	}
	if _, err := (Proxy{BaseURL: upstream.URL, Client: client}).Invoke(context.Background(), validRequest()); err == nil {
		t.Fatal("client trusted an upstream signed by an unrelated CA")
	}
}
