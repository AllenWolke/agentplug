package main

import (
	"context"
	"errors"

	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/knowledge"
)

func knowledgeCachedReceiptCheck(ctx context.Context, request capability.KnowledgeSearchRequest, embedding bool, r knowledge.QueryStageReceipt) error {
	if embedding && r.PromptVersionID != "" || !embedding && r.PromptVersionID != request.Policy.PromptVersionID {
		return knowledge.ErrInvalidQueryStage
	}
	versions := append([]string{r.ModelVersionID}, r.ModelVersionIDs...)
	seen := map[string]bool{}
	for _, version := range versions {
		if seen[version] {
			continue
		}
		seen[version] = true
		if !capability.KnowledgeModelVersionAllowed(request.Policy, version, embedding, request.ModelReceiptCheck != nil) {
			return knowledge.ErrInvalidQueryStage
		}
		if request.ModelReceiptCheck != nil {
			operation := "generate"
			if embedding {
				operation = "embed"
			}
			if err := request.ModelReceiptCheck(ctx, operation, version); err != nil {
				var modelError *capability.KnowledgeModelError
				if errors.As(err, &modelError) && modelError.Status == 403 && (modelError.Code == "MODEL_ACCESS_DENIED" || modelError.Code == "MODEL_SELECTION_MISMATCH" || modelError.Code == "EXTERNAL_MODEL_DENIED") {
					return errors.Join(knowledge.ErrCachedReceiptUnusable, err)
				}
				return err
			}
		}
	}
	return nil
}
