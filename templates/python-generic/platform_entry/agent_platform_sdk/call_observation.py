"""Optional bounded call timing; no request/response/credential logging."""
import asyncio
import hashlib
import json
import logging
import os
import re
import time

_PATHS={"/internal/state/checkpoint","/internal/model/generate","/internal/tool/invoke",
        "/internal/tool/receipt","/internal/knowledge/search","/internal/runtime/harness-policy",
        "/internal/prompt/resolve","/internal/context/renew"}
_NAMESPACES={"harness","harness-v2","step-workflow","knowledge","graph-runtime",
             "checkpoint-cursor","coordination"}
_OPERATIONS={"load","save","load_reference","list_recovery_references","force","opportunistic"}


def enabled():
    return os.getenv("AGENT_PLATFORM_CAPABILITY_TIMING")=="1"


def _emit(event):
    logger=logging.getLogger("agent_platform_sdk.capability_observation")
    if not any(getattr(handler,"_capability_observation",False) for handler in logger.handlers):
        handler=logging.StreamHandler()
        handler._capability_observation=True
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate=False
    logger.info("capability_observation %s",json.dumps(event,separators=(",",":"),allow_nan=False))


async def observed_call(context,path,payload,call):
    if not enabled():
        return await call()
    started=time.perf_counter();code="OK";status="completed"
    try:
        return await call()
    except BaseException as error:
        status="cancelled" if isinstance(error,asyncio.CancelledError) else "failed"
        supplied=getattr(error,"code","")
        code=supplied if isinstance(supplied,str) and re.fullmatch(r"[A-Z0-9_]{1,64}",supplied) else "CALL_FAILED"
        raise
    finally:
        # Timing must never change a send, retry policy, result or cancellation.
        try:
            identity=(context.get("task_id","") if isinstance(context,dict) else getattr(context,"task_id",""))
            run_ref=hashlib.sha256(identity.encode()).hexdigest()[:16] if isinstance(identity,str) else ""
            namespace=payload.get("namespace") if isinstance(payload,dict) else None
            operation=payload.get("operation") if isinstance(payload,dict) else None
            _emit({"version":"capability-observation/v1","run_ref":run_ref,
                "path":path if path in _PATHS else "other",
                "namespace":namespace if isinstance(namespace,str) and namespace in _NAMESPACES else "other",
                "operation":operation if isinstance(operation,str) and operation in _OPERATIONS else "other",
                "elapsed_ms":round(max(0,time.perf_counter()-started)*1000,3),
                "status":status,"code":code})
        except Exception:
            pass
