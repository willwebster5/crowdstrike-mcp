# scripts/spike_fastmcpapp.py
"""
Spike: verify fastmcp.apps.FastMCPApp is a drop-in for mcp.server.fastmcp.FastMCP
for the crowdstrike-mcp server's needs.

Surfaces required:
  - .tool(name=...) decorator (BaseModule._add_tool calls server.tool(**kwargs)(method))
  - .add_resource(resource) (BaseModule._add_resource)
  - .resource(uri, ...) decorator (NGSIEMModule.register_resources uses this)
  - .run(transport="stdio")
  - .sse_app() / .streamable_http_app() (HTTP transports)

Run: python scripts/spike_fastmcpapp.py
Outputs: PASS/FAIL per surface, plus a summary verdict.
"""

from __future__ import annotations

import sys


def check(label: str, fn) -> bool:
    try:
        fn()
        print(f"  PASS  {label}")
        return True
    except Exception as exc:
        print(f"  FAIL  {label}: {type(exc).__name__}: {exc}")
        return False


def main() -> int:
    from fastmcp.apps import FastMCPApp

    app = FastMCPApp("spike-test")
    results: list[bool] = []

    # 1. server.tool() decorator
    def _tool_decorator():
        @app.tool(name="spike_tool")
        def my_tool() -> str:
            return "ok"
    results.append(check(".tool(name=...) decorator", _tool_decorator))

    # 2. server.add_resource(resource)
    def _add_resource():
        from mcp.types import Resource
        # Build a minimal Resource. If FastMCPApp expects a different type,
        # this fail will tell us what to migrate to.
        r = Resource(uri="spike://test", name="spike", description="test")
        app.add_resource(r)
    results.append(check(".add_resource(Resource)", _add_resource))

    # 3. server.resource(uri, ...) decorator
    def _resource_decorator():
        @app.resource("spike://decorator", name="spike-dec", description="d")
        def _payload():
            return "hello"
    results.append(check(".resource(uri, ...) decorator", _resource_decorator))

    # 4. .sse_app() / .streamable_http_app()
    results.append(check(".sse_app()", lambda: app.sse_app()))
    results.append(check(".streamable_http_app()", lambda: app.streamable_http_app()))

    print()
    if all(results):
        print("VERDICT: PASS — proceed with FastMCPApp swap (Task 11).")
        return 0
    print("VERDICT: FAIL — see Task 1 outcomes section of the plan for fallback.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
