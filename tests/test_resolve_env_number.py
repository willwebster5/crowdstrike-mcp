"""Tests for utils.resolve_env_number — the shared env-var-with-fallback parser.

Extracted during the PR #57 follow-up: three call sites (FalconClient's HTTP
timeout, NGSIEMModule's display-row cap, NGSIEMModule's search timeout/poll
interval) each reimplemented "parse env var as number, fall back to default"
independently and inconsistently — one had no fallback at all and let a
malformed value raise into the caller instead of degrading gracefully.
"""

import pytest

from crowdstrike_mcp.utils import resolve_env_number


class TestUnsetAndValid:
    def test_unset_returns_default(self, monkeypatch):
        monkeypatch.delenv("FOO", raising=False)
        assert resolve_env_number("FOO", 42) == 42

    def test_blank_returns_default(self, monkeypatch):
        monkeypatch.setenv("FOO", "   ")
        assert resolve_env_number("FOO", 42) == 42

    def test_valid_value_is_used(self, monkeypatch):
        monkeypatch.setenv("FOO", "17")
        assert resolve_env_number("FOO", 42) == 17

    def test_valid_float_value_is_used(self, monkeypatch):
        monkeypatch.setenv("FOO", "17.5")
        assert resolve_env_number("FOO", 42) == 17.5


class TestUnparseable:
    @pytest.mark.parametrize("bad", ["not-a-number", "12abc", "", " "])
    def test_falls_back_to_default(self, monkeypatch, bad):
        if bad.strip():
            monkeypatch.setenv("FOO", bad)
        else:
            monkeypatch.delenv("FOO", raising=False)
        assert resolve_env_number("FOO", 42) == 42


class TestNonFinite:
    @pytest.mark.parametrize("bad", ["nan", "inf", "-inf", "Infinity"])
    def test_nan_and_inf_fall_back_to_default(self, monkeypatch, bad):
        """float() happily parses these; they must still be rejected.

        This is the exact bug found in FalconClient's original hand-rolled
        version: `value <= 0` alone is False for both nan and inf, so neither
        was caught without an explicit math.isfinite() check.
        """
        monkeypatch.setenv("FOO", bad)
        assert resolve_env_number("FOO", 42) == 42


class TestMinValue:
    def test_value_below_min_falls_back(self, monkeypatch):
        monkeypatch.setenv("FOO", "0")
        assert resolve_env_number("FOO", 42, min_value=1) == 42

    def test_value_at_min_is_accepted_when_inclusive(self, monkeypatch):
        monkeypatch.setenv("FOO", "1")
        assert resolve_env_number("FOO", 42, min_value=1) == 1

    def test_value_at_min_is_rejected_when_exclusive(self, monkeypatch):
        monkeypatch.setenv("FOO", "0")
        assert resolve_env_number("FOO", 42, min_value=0, exclusive_min=True) == 42

    def test_value_above_min_is_accepted_when_exclusive(self, monkeypatch):
        monkeypatch.setenv("FOO", "0.001")
        assert resolve_env_number("FOO", 42, min_value=0, exclusive_min=True) == 0.001

    def test_no_min_value_means_zero_is_valid(self, monkeypatch):
        """A deliberate use case: FALCON_MCP_NGSIEM_TIMEOUT=0 means 'fail fast'."""
        monkeypatch.setenv("FOO", "0")
        assert resolve_env_number("FOO", 42) == 0

    def test_no_min_value_means_negative_is_valid(self, monkeypatch):
        monkeypatch.setenv("FOO", "-5")
        assert resolve_env_number("FOO", 42) == -5
