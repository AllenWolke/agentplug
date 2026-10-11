"""可复用结构切割契约，不给SDK添加模型推理依赖。偏移采用Unicode码点。"""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
import json
import re
from collections.abc import Callable, Mapping
from typing import Protocol, Any

CONTRACT = "pretokenized-document/v1"


class ActualTokenizer(Protocol):
    def count(self, text: str, purpose: str = "document") -> int: ...
    def offsets(self, text: str) -> list[tuple[int, int]]: ...


@dataclass(frozen=True)
class SourceBlock:
    start: int
    end: int
    kind: str
    section_id: str
    page: int | None = None
    parent_start: int | None = None
    parent_end: int | None = None


def _attach_table_notes(text:str,blocks:list[SourceBlock])->list[SourceBlock]:
    merged=[]
    for block in blocks:
        note=text[block.start:block.end].strip().casefold()
        if (merged and merged[-1].kind=='table' and
                note.startswith(('note:','notes:','footnote:','注：','注:','脚注：','脚注:')) and
                not text[merged[-1].end:block.start].strip()):
            parent=merged[-1]
            merged[-1]=SourceBlock(parent.start,block.end,'table',parent.section_id,parent.page)
        else:merged.append(block)
    return merged


def structure_blocks(text: str, normalized: Mapping[str, Any] | None = None) -> list[SourceBlock]:
    """优先复用摄取层结构结果；纯文本保留标题、段落、表格和相邻脚注。"""
    if normalized is not None:
        blocks=[]
        previous=0
        for row in normalized.get("blocks",[]):
            start,end=row["source_start"],row["source_end"]
            if type(start) is not int or type(end) is not int or not 0 <= previous <= start < end <= len(text):
                raise ValueError("invalid normalized source spans")
            if row.get("text",text[start:end])!=text[start:end]:
                raise ValueError("normalized block does not match source")
            blocks.append(SourceBlock(start,end,row.get("type","paragraph"),str(row.get("section_id","")),row.get("page")))
            previous=end
        if not blocks:
            raise ValueError("empty normalized structure")
        return _attach_table_notes(text,blocks)
    blocks=[]
    section="root"
    for index,match in enumerate(re.finditer(r"[^\n](?:[^\n]|\n(?!\s*\n))*",text)):
        body=match.group()
        if re.match(r"(?:#{1,6}\s|第[一二三四五六七八九十百\d]+[章节条]|\d+(?:\.\d+)*[.)]?\s|(?:Article|Art\.)\s)",body,re.I):
            section=f"section-{index}"
        kind="table" if "|" in body or "\t" in body else "paragraph"
        blocks.append(SourceBlock(match.start(),match.end(),kind,section))
    return _attach_table_notes(text,blocks)


def build_artifacts(text: str, *, document_id: str, document_version: str,
                    tokenizer_id: str, tokenizer_revision: str, model_version: str,
                    tokenizer: ActualTokenizer, token_limit: int, overlap_tokens: int = 0,
                    metadata: Mapping[str,str] | None = None,
                    normalized: Mapping[str,Any] | None = None,
                    parent_token_limit: int | None = None) -> dict[str,Any]:
    """保留原文与父块；每个叶子实际完整编码长度独立验证，不截断正文。"""
    if not text or not all((document_id,document_version,tokenizer_id,tokenizer_revision,model_version)):
        raise ValueError("immutable source/model/tokenizer identity required")
    if not 8 <= token_limit <= 131072 or not 0 <= overlap_tokens < token_limit//2:
        raise ValueError("invalid token window")
    if parent_token_limit is None:parent_token_limit=max(2048,token_limit)
    if not token_limit<=parent_token_limit<=131072:raise ValueError('parent window must contain a legal child window')
    if len(text.encode())>32<<20:
        raise ValueError("raw document too large")
    raw_hash=hashlib.sha256(text.encode()).hexdigest()
    config={"contract":CONTRACT,"tokenizer_id":tokenizer_id,"revision":tokenizer_revision,
            "model_version":model_version,"limit":token_limit,"overlap":overlap_tokens,
            "parent_token_limit_embedding_basis":parent_token_limit,"structure":"clauses-tables-notes/v3"}
    config_hash=hashlib.sha256(json.dumps(config,sort_keys=True).encode()).hexdigest()
    leaves,parents=[],[]
    blocks=structure_blocks(text,normalized)
    sections={}
    for block in blocks:
        if block.section_id not in sections:sections[block.section_id]=[block.start,block.end]
        else:sections[block.section_id][1]=block.end
    section_admission={key:end-start<=8192 and tokenizer.count(text[start:end])<=parent_token_limit
                       for key,(start,end) in sections.items()}
    parent_seen=set()
    for block_number,block in enumerate(blocks):
        block_end=block.end
        if block_number+1<len(blocks) and blocks[block_number+1].section_id==block.section_id:
            block_end=blocks[block_number+1].start
        body=text[block.start:block_end]
        parent_start,parent_end=sections[block.section_id]
        parent_scope='complete_section'
        if not section_admission[block.section_id]:
            parent_start,parent_end=block.start,block_end;parent_scope='block_of_oversized_section'
        parent_id=f"{document_id}-p{parent_start}-{parent_end}-{raw_hash[:12]}"
        if parent_id not in parent_seen:
            parent_seen.add(parent_id)
            parents.append({"id":parent_id,"source_start":parent_start,"source_end":parent_end,
                            "section_id":block.section_id,"type":block.kind,"content":text[parent_start:parent_end],
                            "parent_scope":parent_scope,"count_basis":"embedding_tokenizer_not_generation_usage"})
        spans=[]
        if tokenizer.count(body)<=token_limit:
            spans=[(block.start,block_end)]
        else:
            offsets=tokenizer.offsets(body)
            if not offsets:raise ValueError("no body tokenizer offsets")
            token_index=0
            while token_index < len(offsets):
                # 真实offset一次获取；二分只验证当前窗口，不反复Tokenize累积全文。
                # With no overlap, assign tokenizer whitespace gaps to the prior window
                # exactly once so its source spans can be reused as normalized blocks.
                if spans and overlap_tokens == 0:
                    left = spans[-1][1] - block.start
                else:
                    left=0 if token_index==0 else min(offsets[token_index-1][1],offsets[token_index][0])
                lo,hi=token_index+1,min(len(offsets),token_index+token_limit)
                best=None
                while lo<=hi:
                    middle=(lo+hi)//2
                    right=len(body) if middle==len(offsets) else offsets[middle][0]
                    if tokenizer.count(body[left:right])<=token_limit:
                        best=(middle,right);lo=middle+1
                    else:hi=middle-1
                if best is None:raise ValueError("one token cannot fit full encoding overhead")
                stop,right=best
                # 尽量停在句末/表格行，不删除任何原文字节。
                segment=body[left:right]
                boundaries=[m.end() for m in re.finditer(r"[。；;!?！？]\s*|\n",segment)]
                if boundaries and boundaries[-1]>len(segment)//2 and stop<len(offsets):
                    natural=left+boundaries[-1]
                    natural_stop=next((i for i in range(token_index+1,stop+1) if i==len(offsets) or offsets[i][0]>=natural),stop)
                    if natural_stop>token_index:
                        stop=natural_stop
                        candidate_right=len(body) if stop==len(offsets) else offsets[stop][0]
                        if tokenizer.count(body[left:candidate_right])<=token_limit:right=candidate_right
                        else:stop,right=best
                spans.append((block.start+left,block.start+right))
                next_index=max(token_index+1,stop-overlap_tokens)
                if stop==len(offsets):break
                token_index=next_index
        for start,end in spans:
            leaf=text[start:end]
            count=tokenizer.count(leaf)
            if count>token_limit:raise ValueError("silent truncation forbidden")
            leaf_hash=hashlib.sha256(leaf.encode()).hexdigest()
            leaf_id=hashlib.sha256(f"{document_id}|{document_version}|{config_hash}|{start}|{end}|{leaf_hash}".encode()).hexdigest()
            values={**dict(metadata or {}),"chunking_unit":CONTRACT,"tokenizer_id":tokenizer_id,
                "tokenizer_revision":tokenizer_revision,"embedding_model_version":model_version,
                "full_input_tokens":str(count),"source_start":str(start),"source_end":str(end),
                "chunk_body_sha256":leaf_hash,"raw_document_sha256":raw_hash,
                "raw_document_id":document_id,"raw_document_version":document_version,
                "parent_id":parent_id,"section_id":block.section_id,"block_type":block.kind,
                "parent_start":str(parent_start),"parent_end":str(parent_end),"parent_scope":parent_scope,
                "offset_unit":"unicode_codepoint"}
            if block.page is not None:values['page']=str(block.page)
            if len(values)>32 or any(len(k)>64 or not isinstance(v,str) or len(v.encode())>1024 for k,v in values.items()):
                raise ValueError("platform metadata budget exceeded")
            leaves.append({"id":leaf_id,"body":leaf,"metadata":values})
    # 空白不构成检索正文，但所有非空白原文必须可由叶子区间覆盖。
    covered=bytearray(len(text))
    for leaf in leaves:
        start,end=int(leaf['metadata']['source_start']),int(leaf['metadata']['source_end'])
        covered[start:end]=b'\1'*(end-start)
    missing=[i for i,char in enumerate(text) if not char.isspace() and not covered[i]]
    if missing:raise ValueError("source coverage incomplete")
    return {"version":"tokenized-source-artifact/v1","raw_document_id":document_id,
        "raw_document_version":document_version,"raw_document_sha256":raw_hash,
        "configuration":config,"configuration_sha256":config_hash,"parents":parents,
        "documents":leaves,"silent_truncations":0,"non_whitespace_coverage":1.0}


def select_context(references: list[dict[str,Any]], *, count_tokens: Callable[[str],int],
                   token_budget: int, prefix: str = "") -> dict[str,Any]:
    """同版本同片段去重；完整段落准入，不切掉例外、单位或脚注。"""
    if token_budget<=0:raise ValueError("positive context budget required")
    if count_tokens(prefix)>token_budget:
        raise ValueError("context prefix exceeds token budget")
    picked,dropped,seen=[],[],set()
    current=prefix
    for ref in references:
        span=ref.get('source_span',{})
        if isinstance(span,(list,tuple)) and len(span)==2:start,end=span
        elif isinstance(span,Mapping):start,end=span.get('start'),span.get('end')
        elif span is None:start,end=None,None
        else:raise ValueError('invalid source span contract')
        key=(ref.get('source_id'),ref.get('doc_id'),ref.get('document_version'),
             start,end,
             hashlib.sha256(str(ref.get('content','')).encode()).hexdigest())
        if key in seen:continue
        seen.add(key)
        content=str(ref.get('content',''))
        candidate=current+'\n'+content
        if count_tokens(candidate)>token_budget:
            dropped.append({'doc_id':ref.get('doc_id'),'reason':'context_token_budget'})
            continue
        picked.append(ref);current=candidate
    return {'references':picked,'dropped':dropped,'actual_input_tokens':count_tokens(current),
            'token_budget':token_budget,'truncated_references':0}
