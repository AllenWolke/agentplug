"""Public source must not contain retired business implementations."""
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]


def test_retired_business_source_trees_are_absent():
    for relative in ("agents/regulatory_validation", "agents/regulatory_qa",
                     "platform/internal/regulatory", "rag-retrievalOps"):
        assert not (ROOT / relative).exists(), relative
