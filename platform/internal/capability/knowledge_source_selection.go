package capability

import "strings"

// selectKnowledgeSources 仅缩小已鉴权的文档集合，不能增添来源或文档。
// 未显式选择时保持既有接口行为；无来源证据时拒绝选择。
func selectKnowledgeSources(plan KnowledgeDocumentPlan, sources []string) (KnowledgeDocumentPlan, error) {
	if len(sources) == 0 {
		return plan, nil
	}
	if plan.Legacy || len(sources) > 16 {
		return KnowledgeDocumentPlan{}, errKnowledgeDocumentAuthority
	}
	selected, available := map[string]bool{}, map[string]bool{}
	for _, document := range plan.Documents {
		available[document.ProviderID] = true
	}
	for _, source := range sources {
		if source == "" || len(source) > 128 || strings.TrimSpace(source) != source || !available[source] || selected[source] {
			return KnowledgeDocumentPlan{}, errKnowledgeDocumentAuthority
		}
		selected[source] = true
	}
	result := KnowledgeDocumentPlan{}
	for _, document := range plan.Documents {
		if selected[document.ProviderID] {
			result.Documents = append(result.Documents, document)
		}
	}
	return result, nil
}
