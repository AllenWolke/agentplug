package sandbox

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

type statsResponseTransport struct {
	body  string
	calls int
}

func (s *statsResponseTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	s.calls++
	if r.Method != http.MethodGet || r.URL.Host != "localhost" ||
		!strings.HasSuffix(r.URL.Path, "/stats") || r.URL.Query().Get("stream") != "false" || r.URL.Query().Get("one-shot") != "true" {
		panic("unexpected engine statistics request")
	}
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(s.body)), Header: http.Header{}}, nil
}

func TestEngineMeasurementsRejectMissingNumbersForeignContainerAndLargeOutput(t *testing.T) {
	id := strings.Repeat("a", 64)
	for _, body := range []string{
		`{"id":"` + id + `","read":"2026-10-05T00:00:00Z","cpu_stats":{},"memory_stats":{}}`,
		`{"id":"` + strings.Repeat("b", 64) + `","read":"2026-10-05T00:00:00Z","cpu_stats":{"cpu_usage":{"total_usage":0}},"memory_stats":{"usage":0}}`,
		strings.Repeat("x", (256<<10)+1),
	} {
		transport := &statsResponseTransport{body: body}
		if _, ok := readEngineResourceSample(context.Background(), &http.Client{Transport: transport}, id, "1.48"); ok {
			t.Fatal("unsafe or absent statistics became a measurement")
		}
	}
	transport := &statsResponseTransport{}
	if _, ok := readEngineResourceSample(context.Background(), &http.Client{Transport: transport}, "../../foreign", "1.48"); ok || transport.calls != 0 {
		t.Fatal("caller path reached engine")
	}
}

func TestEngineReportedZeroIsDistinctFromMissingMeasurement(t *testing.T) {
	id := strings.Repeat("a", 64)
	transport := &statsResponseTransport{body: `{"id":"` + id + `","read":"2026-10-05T00:00:00Z","cpu_stats":{"cpu_usage":{"total_usage":0}},"memory_stats":{"usage":0}}`}
	sample, ok := readEngineResourceSample(context.Background(), &http.Client{Transport: transport}, id, "1.48")
	if !ok || sample.CPU.Usage.Total == nil || *sample.CPU.Usage.Total != 0 || sample.Memory.Usage == nil {
		t.Fatal("real zero measurement rejected")
	}
}

type diskExecTransport struct {
	t     *testing.T
	id    string
	stage int
}

func (d *diskExecTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Host != "localhost" || request.Method != http.MethodPost && request.Method != http.MethodGet {
		d.t.Fatal("unexpected disk measurement request")
	}
	var status int
	var body []byte
	switch d.stage {
	case 0:
		if request.Method != http.MethodPost || !strings.HasSuffix(request.URL.Path, "/containers/"+d.id+"/exec") {
			d.t.Fatal("unexpected exec create endpoint")
		}
		var payload struct {
			AttachStdin  bool     `json:"AttachStdin"`
			AttachStdout bool     `json:"AttachStdout"`
			AttachStderr bool     `json:"AttachStderr"`
			Tty          bool     `json:"Tty"`
			Privileged   bool     `json:"Privileged"`
			User         string   `json:"User"`
			WorkingDir   string   `json:"WorkingDir"`
			Cmd          []string `json:"Cmd"`
		}
		if json.NewDecoder(request.Body).Decode(&payload) != nil || payload.AttachStdin || !payload.AttachStdout || !payload.AttachStderr || payload.Tty ||
			payload.Privileged || payload.User != "65532:65532" || payload.WorkingDir != "/workspace" ||
			!bytes.Equal([]byte(strings.Join(payload.Cmd, "\x00")), []byte(strings.Join([]string{
				"/bin/stat", "-f", "-c", "%b:%f:%S", "/workspace", "/tmp", "/dev/shm",
			}, "\x00"))) {
			d.t.Fatal("stat executable or arguments were not fixed")
		}
		status, body = http.StatusCreated, []byte(`{"Id":"`+d.id+`"}`)
	case 1:
		if request.Method != http.MethodPost || !strings.HasSuffix(request.URL.Path, "/exec/"+d.id+"/start") {
			d.t.Fatal("unexpected exec start endpoint")
		}
		output := []byte("100:90:4096\n20:10:4096\n8:4:4096\n")
		body = make([]byte, 8+len(output))
		body[0] = 1
		binary.BigEndian.PutUint32(body[4:8], uint32(len(output)))
		copy(body[8:], output)
		status = http.StatusOK
	case 2:
		if request.Method != http.MethodGet || !strings.HasSuffix(request.URL.Path, "/exec/"+d.id+"/json") {
			d.t.Fatal("unexpected exec inspect endpoint")
		}
		status, body = http.StatusOK, []byte(`{"ID":"`+d.id+`","ContainerID":"`+d.id+`","Running":false,"ExitCode":0,"ProcessConfig":{"privileged":false,"user":"65532:65532","tty":false,"entrypoint":"/bin/stat","arguments":["-f","-c","%b:%f:%S","/workspace","/tmp","/dev/shm"]}}`)
	default:
		d.t.Fatal("too many Docker exec requests")
	}
	d.stage++
	return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(body)), Header: http.Header{}}, nil
}

func TestTmpfsUsageUsesOnlyFixedStatAndReportsObservedAllocatedBlocks(t *testing.T) {
	id := strings.Repeat("c", 64)
	transport := &diskExecTransport{t: t, id: id}
	client := &http.Client{Transport: transport}
	used, ok := readTmpfsAllocatedBytes(context.Background(), client, id, "1.48")
	if !ok || used != 24*4096 || transport.stage != 3 {
		t.Fatal("fixed tmpfs sample was not normalized", used, ok, transport.stage)
	}
}

func TestTmpfsUsageRejectsMalformedOrUnboundedStatOutput(t *testing.T) {
	for _, output := range [][]byte{
		[]byte("100:101:4096\n20:10:4096\n8:4:4096\n"),
		[]byte("100:90:0\n20:10:4096\n8:4:4096\n"),
		[]byte("100:90:4096\n20:10:4096\n"),
		[]byte(strings.Repeat("9", 513)),
		[]byte("100:90:4096 /workspace\n20:10:4096\n8:4:4096\n"),
	} {
		if _, ok := parseTmpfsStatOutput(output); ok {
			t.Fatal("invalid stat output became a disk measurement")
		}
	}
}
