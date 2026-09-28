from __future__ import annotations

from typing import Any, Callable

from aegis.schema.models import RecommendedAction

ToolFn = Callable[[dict[str, Any]], str]


class SandboxDenied(RuntimeError):
    pass


class ExecutionSandbox:
    """Allowlisted tools only. No shell. No network. No filesystem writes."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolFn] = {}

    def register(self, name: str, fn: ToolFn) -> None:
        self._tools[name] = fn

    def execute(self, action: RecommendedAction, approved: bool) -> str:
        if action.tool_name not in self._tools:
            raise SandboxDenied(f"tool not allowlisted: {action.tool_name}")
        if action.requires_approval and not approved:
            raise SandboxDenied(f"approval required for {action.tool_name}")
        return self._tools[action.tool_name](action.tool_args)


def default_tools() -> dict[str, ToolFn]:
    def isolate_host(args: dict[str, Any]) -> str:
        host = args.get("host", "unknown")
        return f"[SIMULATED] EDR isolation requested for {host}. Ticket opened. Host remains reachable until SOC confirms."

    def disable_user(args: dict[str, Any]) -> str:
        user = args.get("user", "unknown")
        return f"[SIMULATED] IdP disable queued for {user}. Requires IAM second-person confirm."

    def block_domain(args: dict[str, Any]) -> str:
        domain = args.get("domain", "unknown")
        return f"[SIMULATED] Proxy/DNS block proposed for {domain}. Not pushed to prod."

    def kill_process(args: dict[str, Any]) -> str:
        return f"[SIMULATED] Process containment proposed: {args.get('process')} on {args.get('host')}"

    def query_telemetry(args: dict[str, Any]) -> str:
        return f"[READ] telemetry query accepted filters={args}"

    def enrich_hash(args: dict[str, Any]) -> str:
        h = args.get("hash", "")
        if h.startswith("eicar") or h.endswith("bad"):
            return f"[READ] hash {h} reputation=malicious sources=3/4"
        return f"[READ] hash {h} reputation=unknown/low-confidence"

    return {
        "isolate_host": isolate_host,
        "disable_user": disable_user,
        "block_domain": block_domain,
        "kill_process": kill_process,
        "query_telemetry": query_telemetry,
        "enrich_hash": enrich_hash,
    }
