"""Safe execution error taxonomy. / 不回传原始业务数据的稳定执行错误分类。"""

from __future__ import annotations

import httpx

from .capability_client import GatewayError, _child_stop_control_error_details
from .models import AppError


class DomainExecutionError(RuntimeError):
    """Business hooks explicitly reject input before side effects.

    业务 Hook 在副作用前显式拒绝；message 只能使用非敏感的固定说明。
    """

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


DOMAIN_CODES = {
    "UNSUPPORTED_REPORT_TYPE",
    "RULE_BUNDLE_EMPTY",
    "NO_APPLICABLE_RULE_RESULTS",
    "INVALID_REVIEW_DECISION",
    "INSUFFICIENT_EVIDENCE",
    "INVALID_REQUEST",
    "RULE_BUNDLE_INVALID",
    "REPORT_BATCH_NOT_FOUND",
    "DATA_READINESS_FAILED",
}
DENIED_CODES = {
	"EXTERNAL_MODEL_DENIED",
	"DEVELOPMENT_MODEL_DENIED",
    "POLICY_DENIED",
    "CAPABILITY_DENIED",
    "MODEL_ACCESS_DENIED",
    "AUTHORIZATION_REVOKED",
    "PERMISSION_DENIED",
    "PROMPT_VERSION_DENIED",
    "CAPABILITY_RENEWAL_DENIED",
    "KNOWLEDGE_SOURCES_DENIED",
    "KNOWLEDGE_DOCUMENTS_DENIED",
    "KNOWLEDGE_SCOPE_DENIED",
    "KNOWLEDGE_POLICY_DENIED",
    "MEMORY_POLICY_DENIED",
    "TOOL_CONFIRMATION_REQUIRED",
    "TOOL_CONFIRMATION_DENIED",
}


def classify_execution_error(exc: Exception) -> tuple[int, AppError]:
    """Return fixed messages only; never use upstream exception text.

    仅使用固定错误说明，禁止回传异常正文、提示词或上游响应。
    """
    if isinstance(exc, DomainExecutionError):
        if exc.code in {
            "EXECUTION_ALREADY_ACTIVE",
            "CANCELLATION_NOT_CONFIRMED",
            "EXECUTION_CANCELLED",
            "EXECUTION_START_UNCONFIRMED",
            "EXECUTION_CAPACITY_EXCEEDED",
            "RUN_GENERATION_UNVERIFIED",
            "RUN_RESULT_UNCONFIRMED",
            "RUN_RESUME_UNCONFIRMED",
            "RUN_HANDOFF_UNCONFIRMED",
        }:
            return 409, AppError(
                code=exc.code,
                message="execution supervision conflict",
                retryable=exc.code == "CANCELLATION_NOT_CONFIRMED",
            )
        code = exc.code if exc.code in DOMAIN_CODES else "INVALID_REQUEST"
        return 422, AppError(
            code=code, message="business request rejected", retryable=False
        )
    if isinstance(exc, PermissionError):
        return 403, AppError(
            code="PERMISSION_DENIED",
            message="operation not authorized",
            retryable=False,
        )
    if isinstance(exc, ValueError):
        prefix = str(exc).partition(":")[0]
        # Pure domain libraries may expose a public code without importing SDK.
        # 纯领域库可声明安全公共码，不必反向依赖 SDK；仍只接受固定白名单。
        declared = getattr(exc, "public_code", prefix)
        code = (
            declared
            if isinstance(declared, str) and declared in DOMAIN_CODES
            else "INVALID_REQUEST"
        )
        return 422, AppError(
            code=code, message="business input is invalid", retryable=False
        )
    if isinstance(exc, (TimeoutError, httpx.TimeoutException)):
        return 504, AppError(
            code="UPSTREAM_TIMEOUT", message="upstream call timed out", retryable=True
        )
    if isinstance(exc, httpx.TransportError):
        return 503, AppError(
            code="CAPABILITY_UNAVAILABLE",
            message="upstream transport unavailable",
            retryable=True,
        )
    if isinstance(exc, GatewayError):
        if exc.code == "MODEL_OUTPUT_INCOMPLETE":
            return 502, AppError(
                code=exc.code, message="model output incomplete; known usage retained", retryable=False,
            )
        if exc.code == "MODEL_BUDGET_EXCEEDED":
            return 402, AppError(
                code=exc.code, message="governed model budget exhausted", retryable=False,
            )
        if exc.code == "AGENT_STOP_REVISION_CONFLICT":
            return 409, AppError(
                code=exc.code,
                message="child stop state changed; explicit revision retry required",
                retryable=False,
                details=_child_stop_control_error_details(exc.code, 409, exc.details),
            )
        if exc.code in {"TOOL_RESULT_UNKNOWN", "TOOL_RECONCILIATION_REQUIRED"}:
            return 409, AppError(code=exc.code, message="tool effect requires reconciliation", retryable=False)
        if exc.code == "TOOL_OBSERVATION_REJECTED":
            return 502, AppError(code=exc.code, message="tool observation invalid or incomplete", retryable=False)
        if exc.code in DOMAIN_CODES:
            return 422, AppError(
                code=exc.code, message="business request rejected", retryable=False
            )
        if exc.code == "UPSTREAM_TIMEOUT":
            return 504, AppError(
                code=exc.code, message="upstream call timed out", retryable=True
            )
        if exc.code in {
            "INVALID_GATEWAY_RESPONSE",
            "INVALID_TOOL_RESPONSE",
            "GATEWAY_RESPONSE_TOO_LARGE",
        }:
            return 502, AppError(
                code="UPSTREAM_PROTOCOL_ERROR",
                message="upstream protocol invalid",
                retryable=False,
            )
        if exc.code in DENIED_CODES:
            return 403, AppError(
                code=exc.code, message="capability policy denied", retryable=False
            )
        return 503, AppError(
            code="CAPABILITY_UNAVAILABLE",
            message="upstream capability unavailable",
            retryable=True,
        )
    return 500, AppError(
        code="INTERNAL_ERROR", message="execution failed", retryable=False
    )
