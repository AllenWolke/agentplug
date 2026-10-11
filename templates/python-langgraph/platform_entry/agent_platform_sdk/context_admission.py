"""Whole-evidence admission; never label a byte bound as actual tokenizer usage."""
from __future__ import annotations
from collections.abc import Callable
from typing import Any
import hashlib,json


def admit_messages(references:list[dict[str,Any]], *,
                   build_messages:Callable[[list[dict[str,Any]]],list[dict[str,str]]],
                   maximum_input_tokens:int,
                   count_messages:Callable[[list[dict[str,str]]],int]|None=None,
                   tokenizer_identity:str|None=None)->dict[str,Any]:
    if not 128<=maximum_input_tokens<=131072:
        raise ValueError('invalid whole-message input budget')
    if (count_messages is None)!=(tokenizer_identity is None):
        raise ValueError('actual counter and immutable tokenizer identity must be supplied together')
    if count_messages is None:
        # UTF-8 byte-level bound with explicit framing allowance. The model
        # gateway remains the authority for model-specific context/usage.
        def counter(messages):
            return 256+sum(64+len(message.get('role','').encode())+
                           len(message.get('content','').encode()) for message in messages)
        basis='conservative_utf8_bytes_plus_framing'
    else:
        counter=count_messages;basis='actual_generation_tokenizer'
    picked=[];dropped=[];seen=set()
    if counter(build_messages([]))>maximum_input_tokens:
        raise ValueError('prompt and user input exceed input budget')
    for reference in references:
        content=str(reference.get('content',''))
        identity=(reference.get('source_id',reference.get('source')),
                  reference.get('doc_id'),reference.get('document_version',reference.get('kb_version')),
                  json.dumps(reference.get('source_span',{}),sort_keys=True),hashlib.sha256(content.encode()).hexdigest())
        if identity in seen:continue
        seen.add(identity)
        if counter(build_messages([*picked,reference]))>maximum_input_tokens:
            dropped.append({'doc_id':reference.get('doc_id'),'reason':'whole_message_input_budget'})
        else:picked.append(reference)
    messages=build_messages(picked)
    measurement={'admission_basis':basis,'tokenizer_identity':tokenizer_identity,
                 'input_bound':counter(messages),'maximum_input_tokens':maximum_input_tokens,
                 'actual_generation_input_tokens':counter(messages) if count_messages else None,
                 'dropped_evidence':dropped,'truncated_references':0}
    return {'references':picked,'messages':messages,'measurement':measurement}
