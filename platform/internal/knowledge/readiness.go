package knowledge

import "context"

// ActiveGeneration is a read-only version fence for composition-owned cache
// keys. Search captures its own repeatable-read generation; this is not a
// historical authorization source or an Agent-selected version.
func (p PostgresProjection) ActiveGeneration(ctx context.Context, scope ProjectionScope) (Generation, int64, error) {
	var generation Generation
	var revision int64
	if p.DB == nil || !scope.valid() {
		return generation, 0, ErrInvalidProjection
	}
	err := p.DB.QueryRowContext(ctx, `SELECT g.generation_id,g.embedding_model_version,g.dimensions,a.revision FROM knowledge.active_generations a JOIN knowledge.generations g USING (tenant_id,department_id,application_id,knowledge_id,generation_id) WHERE a.tenant_id=$1 AND a.department_id=$2 AND a.application_id=$3 AND a.knowledge_id=$4 AND g.state='ready' AND g.tokenizer_version=$5`, append(scope.args(), TokenizerVersion)...).Scan(&generation.ID, &generation.EmbeddingModelVersion, &generation.Dimensions, &revision)
	return generation, revision, err
}

func (p PostgresProjection) Ready(ctx context.Context) error {
	if p.DB == nil {
		return ErrInvalidProjection
	}
	rows, err := p.DB.QueryContext(ctx, `SELECT g.generation_id,g.embedding_model_version,g.dimensions,c.chunk_id,c.document_version,c.acl_revision,c.embedding,a.revision FROM knowledge.generations g JOIN knowledge.chunks c USING(tenant_id,department_id,application_id,knowledge_id,generation_id) JOIN knowledge.active_generations a USING(tenant_id,department_id,application_id,knowledge_id,generation_id) LIMIT 0`)
	if err != nil {
		return err
	}
	return rows.Close()
}

func (p PostgresSource) Ready(ctx context.Context) error {
	if p.DB == nil {
		return ErrInvalidProjection
	}
	rows, err := p.DB.QueryContext(ctx, `SELECT s.source_revision,h.document_id,v.payload FROM platform_knowledge_source_head s JOIN platform_knowledge_document_head h USING(tenant_id,department_id,application_id,knowledge_id) JOIN platform_knowledge_document_version v USING(tenant_id,department_id,application_id,knowledge_id,document_id,document_version) LIMIT 0`)
	if err != nil {
		return err
	}
	return rows.Close()
}
