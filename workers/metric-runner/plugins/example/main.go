// Command example is the reference third-party metric plugin used by the PF-16
// tests and by the plugin pilot. It is a real, separately built binary that
// speaks only the frozen plugin contract: it reads one strict JSON request from
// stdin and writes one JSON response to stdout. It never reaches the network,
// never reads platform state and never touches a secret, so it demonstrates the
// compliant shape an operator is expected to register.
// Command example 是 PF-16 测试与插件试点所使用的第三方指标插件参考实现。它是一份真实、
// 独立构建的二进制，只讲冻结的插件契约：从 stdin 读取一份严格 JSON 请求，向 stdout 写一份 JSON
// 响应。它不访问网络、不读取平台状态、不触碰密钥，因此展示了运维应当注册的合规形态。
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/lexagent/metric-runner/internal/protocol"
)

// maxRequestBytes bounds the request this reference plugin is willing to buffer.
// maxRequestBytes 限定本参考插件愿意缓冲的请求大小。
const maxRequestBytes = 4 << 20

func main() {
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, maxRequestBytes))
	if err != nil || len(raw) == 0 {
		fail("read metric plugin request")
	}
	var req protocol.PluginRequest
	if err := protocol.DecodeStrict(raw, &req); err != nil {
		fail("strict decode of metric plugin request: " + err.Error())
	}
	emit(answer(req))
}

// answer is the reference computation: a plain bounded ratio over the counts it
// was handed. Zero samples stay UNKNOWN rather than becoming a perfect score.
// answer 是参考计算：对收到的计数做一次有界比例运算。零样本保持 UNKNOWN，不会变成满分。
func answer(req protocol.PluginRequest) protocol.PluginResponse {
	if req.Total <= 0 || req.Correct < 0 || req.Correct > req.Total {
		return protocol.PluginResponse{Status: protocol.PluginStatusUnknown, Reason: "no usable counts"}
	}
	value := float64(req.Correct) / float64(req.Total)
	return protocol.PluginResponse{
		Status:      protocol.PluginStatusOK,
		Numerator:   float64(req.Correct),
		Denominator: float64(req.Total),
		Value:       &value,
	}
}

func emit(response protocol.PluginResponse) {
	raw, err := json.Marshal(response)
	if err != nil {
		fail("encode metric plugin response")
	}
	fmt.Println(string(raw))
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
