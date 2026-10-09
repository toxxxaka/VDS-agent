"""Bearer-protected Streamable HTTP MCP endpoint for VDS-Agent."""
from __future__ import annotations

import json
import os
import secrets

from .agent_tools import ToolError, execute

try:
    import uvicorn
    from mcp.server.fastmcp import FastMCP
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import JSONResponse
except ImportError:  # Keeps unrelated local unit tests runnable before dependencies are installed.
    uvicorn = FastMCP = BaseHTTPMiddleware = Request = JSONResponse = None

TOKEN_ENV = "MONITORINGBOT_MCP_TOKEN"


def _token_valid(value: str) -> bool:
    token = os.environ.get(TOKEN_ENV, "")
    return bool(token) and secrets.compare_digest(value, f"Bearer {token}")


if BaseHTTPMiddleware is not None:
    class BearerTokenMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            if request.url.path == "/healthz":
                return JSONResponse({"ok": True}, headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})
            if not _token_valid(request.headers.get("authorization", "")):
                return JSONResponse({"error": "unauthorized"}, status_code=401, headers={"WWW-Authenticate": "Bearer", "Cache-Control": "no-store"})
            response = await call_next(request)
            response.headers["Cache-Control"] = "no-store"
            response.headers["X-Content-Type-Options"] = "nosniff"
            return response


def _call(name: str, arguments: dict | None = None) -> dict:
    try:
        return execute(name, arguments or {}, actor="mcp")
    except ToolError as error:
        return {"ok": False, "error": str(error)}


def build_mcp():
    if FastMCP is None:
        raise RuntimeError("MCP dependencies are not installed")
    mcp = FastMCP(
        "vds-agent",
        instructions=(
            "Private VDS diagnostics and controlled operations. Diagnose before recommending action. "
            "Administrative actions require an explicit two-step confirmation from the operator."
        ),
        host="127.0.0.1",
        port=int(os.environ.get("MONITORINGBOT_MCP_PORT", "8793")),
        streamable_http_path="/mcp",
        stateless_http=True,
    )

    @mcp.tool()
    def server_status() -> dict:
        """Read current CPU, RAM, uptime, disk and network state."""
        return _call("server_status")

    @mcp.tool()
    def diagnose_load(limit: int = 10) -> dict:
        """Diagnose CPU, RAM and I/O pressure and list top processes."""
        return _call("diagnose_load", {"limit": limit})

    @mcp.tool()
    def process_inspect(sort: str = "cpu", limit: int = 15, pid: int | None = None) -> dict:
        """Inspect bounded process metadata by CPU or memory, optionally by PID."""
        return _call("process_inspect", {"sort": sort, "limit": limit, "pid": pid})

    @mcp.tool()
    def service_status(units: list[str] | None = None) -> dict:
        """Read status of explicitly named systemd service units."""
        return _call("service_status", {"units": units} if units is not None else {})

    @mcp.tool()
    def service_logs(unit: str = "monitoringbot.service", lines: int = 40, minutes: int = 60) -> dict:
        """Read a bounded, redacted journal excerpt for one service."""
        return _call("service_logs", {"unit": unit, "lines": lines, "minutes": minutes})

    @mcp.tool()
    def metrics_query(range: str = "1h") -> dict:
        """Read local metrics for 1h, 6h, 24h, 7d or 30d."""
        return _call("metrics_query", {"range": range})

    @mcp.tool()
    def incidents_query(status: str = "active") -> dict:
        """Read active, closed or all monitoring incidents."""
        return _call("incidents_query", {"status": status})

    @mcp.tool()
    def network_diagnostics(host: str, port: int = 443, https: bool = False, icmp: bool = False) -> dict:
        """Run bounded DNS, TCP, optional HTTPS and ICMP checks for a public host."""
        return _call("network_diagnostics", {"host": host, "port": port, "https": https, "icmp": icmp})

    @mcp.tool()
    def monitoring_health() -> dict:
        """Read VDS-Agent self-monitoring health."""
        return _call("monitoring_health")

    @mcp.tool()
    def admin_action(action: str, confirmation_id: int | None = None) -> dict:
        """Prepare then confirm one allow-listed high-risk administrative action."""
        arguments = {"action": action}
        if confirmation_id is not None:
            arguments["confirmation_id"] = confirmation_id
        return _call("admin_action", arguments)

    return mcp


def main() -> None:
    if not os.environ.get(TOKEN_ENV):
        raise SystemExit(f"{TOKEN_ENV} is required")
    if FastMCP is None or uvicorn is None:
        raise SystemExit("Install dependencies from requirements.txt")
    app = build_mcp().streamable_http_app()
    app.add_middleware(BearerTokenMiddleware)
    uvicorn.run(app, host="127.0.0.1", port=int(os.environ.get("MONITORINGBOT_MCP_PORT", "8793")), log_level="info")


if __name__ == "__main__":
    main()
