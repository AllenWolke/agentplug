"""Consume platform-authorized parent evidence without resolving private source data locally."""
from __future__ import annotations
from typing import Any
import hashlib


def parent_evidence_references(references:list[dict[str,Any]])->list[dict[str,Any]]:
    result=[];seen=set()
    for reference in references:
        if reference.get('parent_context_status') in {
                'incomplete_authorized_siblings','bounded_scope_lookup_unavailable','current_authority_unavailable',
                'section_exceeds_context_limit'}:
            continue
        parent=reference.get('parent_context')
        if parent is None:
            result.append(reference);continue
        if (not isinstance(parent,dict) or parent.get('schema_version')!='authorized-parent-context/v1' or
                not isinstance(parent.get('source_documents'),list) or not parent['source_documents'] or
                not isinstance(parent.get('content'),str) or not parent['content']):
            raise ValueError('invalid governed parent context')
        start,end=parent['source_span']
        if type(start) is not int or type(end) is not int or start<0 or end-start!=len(parent['content']):
            raise ValueError('parent original-source span mismatch')
        identity=(reference.get('source'),reference.get('raw_document_id'),reference.get('raw_document_version'),
                  reference.get('parent_id'),start,end,hashlib.sha256(parent['content'].encode()).hexdigest())
        if identity in seen:continue
        seen.add(identity)
        result.append({**reference,'retrieved_child_content':reference.get('retrieved_child_content',reference['content']),
            'content':parent['content'],'source_span':parent['source_span'],
            'evidence_context_kind':'authorized_complete_parent','parent_context':parent})
    return result
