import pytest
from agent_platform_sdk.token_artifacts import build_artifacts,select_context


class FixtureTokenizer:
    # 确定性单位测试桩，真实Tokenizer由独立模型集成实验验证。
    def count(self,text,purpose='document'):return len(text)+2
    def offsets(self,text):return [(i,i+1) for i in range(len(text))]


def build(text,**kwargs):
    return build_artifacts(text,document_id='raw-document',document_version='1',tokenizer_id='fixture',
        tokenizer_revision='fixture-v1',model_version='fixture-model-v1',tokenizer=FixtureTokenizer(),token_limit=24,**kwargs)


def test_unicode_offsets_body_digest_and_full_prefix_budget_preserved():
    text='第1条：比例不低于8%，但过渡期除外。\n\n| 项目 | 单位 |\n| 贷款 | 万元 |'
    result=build(text)
    assert result['non_whitespace_coverage']==1 and result['silent_truncations']==0
    for leaf in result['documents']:
        metadata=leaf['metadata']
        assert leaf['body']==text[int(metadata['source_start']):int(metadata['source_end'])]
        assert int(metadata['full_input_tokens'])<=24
    assert any(leaf['metadata']['block_type']=='table' for leaf in result['documents'])


def test_complete_section_includes_interparagraph_and_tokenizer_whitespace_gaps():
    import re
    class SparseOffsets:
        def count(self,text,purpose='document'):return len(re.findall(r'\S+',text))+2
        def offsets(self,text):return [match.span() for match in re.finditer(r'\S+',text)]
    text='# Rule\n\nThe ratio is at least eight percent.\n\nException: approved suspension changes only the deadline.\n'
    result=build_artifacts(text,document_id='raw',document_version='v1',tokenizer_id='sparse',
        tokenizer_revision='v1',model_version='v1',tokenizer=SparseOffsets(),token_limit=8)
    assert len(result['parents'])==1
    parent=result['parents'][0]
    coverage=set()
    for leaf in result['documents']:
        metadata=leaf['metadata'];start,end=int(metadata['source_start']),int(metadata['source_end'])
        assert leaf['body']==text[start:end] and leaf['body'].strip()
        coverage.update(range(start,end))
    assert set(range(parent['source_start'],parent['source_end']))<=coverage


def test_oversized_section_is_explicit_and_not_used_as_complete_evidence():
    from agent_platform_sdk.evidence_context import parent_evidence_references
    result=build('规则正文：'+('a'*70),parent_token_limit=30)
    assert all(row['metadata']['parent_scope']=='block_of_oversized_section' for row in result['documents'])
    assert parent_evidence_references([{'content':'局部正文','parent_context_status':'section_exceeds_context_limit'}])==[]


def test_configuration_change_changes_leaf_identity_and_no_empty_chunks():
    text='教学规则正文：比率不低于8%，业务例外仍需审核。'
    first=build(text);second=build(text,overlap_tokens=2)
    assert first['configuration_sha256']!=second['configuration_sha256']
    assert all(leaf['body'] for leaf in second['documents'])
    assert {leaf['id'] for leaf in first['documents']}!={leaf['id'] for leaf in second['documents']}


def test_same_document_different_versions_not_deduplicated_or_partially_truncated():
    refs=[{'doc_id':'a','document_version':'1','content':'旧版规则'},
          {'doc_id':'a','document_version':'2','content':'新版规则，保留例外'}]
    result=select_context(refs,count_tokens=lambda text:len(text),token_budget=100)
    assert len(result['references'])==2 and result['truncated_references']==0
    bounded=select_context(refs,count_tokens=lambda text:len(text),token_budget=10)
    assert len(bounded['references'])==1 and bounded['dropped'][0]['reason']=='context_token_budget'


def test_zero_overlap_sparse_offsets_round_trip_through_structural_contract():
    import re
    class SparseOffsets:
        def count(self, text, purpose='document'): return len(re.findall(r'\S+', text)) + 2
        def offsets(self, text): return [match.span() for match in re.finditer(r'\S+', text)]
    text = 'one two three four five six seven eight nine ten eleven twelve'
    kwargs = dict(document_id='raw', document_version='v1', tokenizer_id='sparse',
                  tokenizer_revision='v1', model_version='v1', tokenizer=SparseOffsets(), token_limit=8)
    result = build_artifacts(text, **kwargs)
    spans = [(int(leaf['metadata']['source_start']), int(leaf['metadata']['source_end']))
             for leaf in result['documents']]
    assert len(spans) > 1
    assert all(left[1] == right[0] for left, right in zip(spans, spans[1:]))
    assert ''.join(leaf['body'] for leaf in result['documents']) == text
    normalized = {'blocks': [dict(source_start=start, source_end=end, text=text[start:end],
                                section_id='common') for start, end in spans]}
    rebuilt = build_artifacts(text, normalized=normalized, **kwargs)
    assert rebuilt['non_whitespace_coverage'] == 1.0
    assert [(int(leaf['metadata']['source_start']), int(leaf['metadata']['source_end']))
            for leaf in rebuilt['documents']] == spans


def test_requested_overlap_remains_explicit_in_source_ranges():
    result = build('abcdefghijklmnopqrstuvwxyz' * 3, overlap_tokens=2)
    spans = [(int(leaf['metadata']['source_start']), int(leaf['metadata']['source_end']))
             for leaf in result['documents']]
    assert any(right[0] < left[1] for left, right in zip(spans, spans[1:]))
    assert result['non_whitespace_coverage'] == 1.0
