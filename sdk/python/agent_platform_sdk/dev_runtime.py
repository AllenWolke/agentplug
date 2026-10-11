"""Explicit development/test-only local run provider.

Production Agents must use the Platform Run Gateway.  This module is the only
named escape hatch for isolated local development and tests; it is imported
lazily by Agent startup only when ``PLATFORM_RUN_EXECUTOR=local`` is explicit.
生产 Agent 必须使用平台 Run Gateway；本模块仅供显式本地开发和单测。
"""

from .local_runtime import build_local_run_provider

__all__ = ["build_local_run_provider"]
