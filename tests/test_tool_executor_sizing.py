"""BaseModule._ensure_tool_executor gives offloaded tool calls a sized thread pool.

Follow-up to PR #57 (fix/blocking-io-wedges-server): asyncio.to_thread submits
every offloaded tool call to the running loop's *default* executor, which
Python creates lazily as ThreadPoolExecutor(max_workers=min(32,
os.cpu_count()+4)) — as few as ~9 threads in a constrained container. Searches
hold a worker for their entire runtime, so a burst of concurrent long-running
calls at real-world scale (the field report's own reproduction used ~137
concurrent subagents) can exhaust that default pool and queue new calls behind
it with no visible signal — a smaller-scale reprise of the wedge this offload
exists to prevent.
"""

import asyncio

import pytest

import crowdstrike_mcp.modules.base as base_module


@pytest.fixture(autouse=True)
def _reset_executor_install_flag(monkeypatch):
    """The install-once flag is a module global; reset it so tests don't leak state."""
    monkeypatch.setattr(base_module, "_executor_installed", False)
    yield
    monkeypatch.setattr(base_module, "_executor_installed", False)


def test_default_executor_is_resized_above_the_stdlib_default(monkeypatch):
    monkeypatch.delenv("FALCON_MCP_TOOL_THREADS", raising=False)

    async def scenario():
        base_module._ensure_tool_executor()
        loop = asyncio.get_running_loop()
        return loop._default_executor

    executor = asyncio.run(scenario())
    assert executor is not None
    assert executor._max_workers == base_module.DEFAULT_TOOL_THREADS
    assert executor._max_workers > 32, "must exceed asyncio's own stdlib default ceiling"


def test_pool_size_is_operator_tunable(monkeypatch):
    monkeypatch.setenv("FALCON_MCP_TOOL_THREADS", "128")

    async def scenario():
        base_module._ensure_tool_executor()
        loop = asyncio.get_running_loop()
        return loop._default_executor

    executor = asyncio.run(scenario())
    assert executor._max_workers == 128


def test_installed_only_once_per_process(monkeypatch):
    """A second call must not replace an already-installed executor."""
    monkeypatch.delenv("FALCON_MCP_TOOL_THREADS", raising=False)

    async def scenario():
        base_module._ensure_tool_executor()
        first = asyncio.get_running_loop()._default_executor
        base_module._ensure_tool_executor()
        second = asyncio.get_running_loop()._default_executor
        return first, second

    first, second = asyncio.run(scenario())
    assert first is second
