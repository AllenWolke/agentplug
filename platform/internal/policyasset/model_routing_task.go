package policyasset

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

var routingTaskDate = regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}\b`)

// BindRoutingTask classifies the original business payload, never a rendered
// Prompt or a client-supplied complexity label. Only its digest/tier is stored.
func BindRoutingTask(binding ModelSelectionBinding, raw json.RawMessage, p ModelRoutingPolicy) (ModelSelectionBinding, error) {
	if binding.Selection.EffectiveMode() != "automatic" {
		return binding, nil
	}
	if p.Validate() != nil || len(raw) == 0 || len(raw) > 128*1024 {
		return ModelSelectionBinding{}, ErrMissingPolicy
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var task map[string]any
	if d.Decode(&task) != nil || task == nil || d.Decode(new(any)) != io.EOF {
		return ModelSelectionBinding{}, ErrMissingPolicy
	}
	delete(task, "policy_snapshot")
	canonical, err := json.Marshal(task)
	if err != nil {
		return ModelSelectionBinding{}, ErrMissingPolicy
	}
	values, nodes := []string{}, 0
	var collect func(any, int) bool
	collect = func(value any, depth int) bool {
		nodes++
		if nodes > 4096 || depth > 16 {
			return false
		}
		switch value := value.(type) {
		case string:
			values = append(values, value)
		case []any:
			for _, item := range value {
				if !collect(item, depth+1) {
					return false
				}
			}
		case map[string]any:
			keys := make([]string, 0, len(value))
			for key := range value {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				if !collect(value[key], depth+1) {
					return false
				}
			}
		}
		return true
	}
	if !collect(task, 0) {
		return ModelSelectionBinding{}, ErrMissingPolicy
	}
	text := strings.ToLower(strings.Join(values, "\n"))
	dates := map[string]bool{}
	for _, date := range routingTaskDate.FindAllString(text, -1) {
		dates[date] = true
	}
	complex := len(dates) > 1 || int64(len(canonical)) >= p.ComplexMinInputTokens
	for _, term := range []string{"比较", "对比", "跨版本", "分别", "多个", "多步骤", "分析原因", "推导", "compare", "contrast", "multi-step", "reason why"} {
		complex = complex || strings.Contains(text, term)
	}
	binding.TaskComplexity = "complex"
	if !complex {
		// A short question can still contain several mandatory conditions. These
		// generic signals promote it to medium; no business vocabulary is needed.
		constraints := false
		for _, term := range []string{"完整", "必须", "保留", "同时", "条件", "全部", "including", "must include", "all conditions", "preserve", "complete definition"} {
			constraints = constraints || strings.Contains(text, term)
		}
		for _, term := range []string{"定义", "是什么", "计算", "提取", "翻译", "what is", "calculate", "extract", "translate"} {
			if strings.Contains(text, term) {
				binding.TaskComplexity = "medium"
				if !constraints && int64(len(canonical)) <= p.SimpleMaxInputTokens {
					binding.TaskComplexity = "simple"
				}
				break
			}
		}
	}
	binding.TaskSHA256 = fmt.Sprintf("%x", sha256.Sum256(canonical))
	return binding, nil
}
