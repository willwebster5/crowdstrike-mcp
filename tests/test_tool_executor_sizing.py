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
def _reset_sized_loops():
    """_sized_loops is a module-global WeakSet; clear it so tests don't leak state."""
    base_module._sized_loops.clear()
    yield
    base_module._sized_loops.clear()


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


def test_installed_only_once_per_loop(monkeypatch):
    """A second call on the SAME loop must not replace an already-installed executor."""
    monkeypatch.delenv("FALCON_MCP_TOOL_THREADS", raising=False)

    async def scenario():
        base_module._ensure_tool_executor()
        first = asyncio.get_running_loop()._default_executor
        base_module._ensure_tool_executor()
        second = asyncio.get_running_loop()._default_executor
        return first, second

    first, second = asyncio.run(scenario())
    assert first is second


def test_a_second_independent_event_loop_also_gets_sized(monkeypatch):
    """Each event loop must get its own sized executor, not just the first one.

    A bare process-global "installed" flag (the original implementation) would
    incorrectly no-op for a second, independent event loop in the same
    process — e.g. an embedder or test harness calling into the tool-offload
    path across more than one loop — silently leaving that loop with
    asyncio's small stdlib default and no signal that happened.
    """
    monkeypatch.delenv("FALCON_MCP_TOOL_THREADS", raising=False)

    async def scenario():
        base_module._ensure_tool_executor()
        return asyncio.get_running_loop()._default_executor

    first_loop_executor = asyncio.run(scenario())
    second_loop_executor = asyncio.run(scenario())

    assert first_loop_executor is not None
    assert second_loop_executor is not None
    assert second_loop_executor is not first_loop_executor, "the second loop reused the first loop's (closed) executor object"
    assert second_loop_executor._max_workers == base_module.DEFAULT_TOOL_THREADS, (
        "the second loop fell through to asyncio's stdlib default instead of being sized"
    )
