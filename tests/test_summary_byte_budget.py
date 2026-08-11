"""_extract_summary fills the byte budget it was given, not a flat line count.

The truncation TRIGGER is a character threshold (LARGE_RESPONSE_THRESHOLD), but
the survivor used to be a flat 40 lines with no relation to it — so most of the
budget went unspent. correlation_list_rules renders ~353 chars per record: 40
lines meant 6 records and 1,860 of the ~18,000 characters available, discarding
90% of the allowance.

It also penalised renderers arbitrarily. A tool printing one line per record kept
38 of them; one printing six lines per record kept 6, for no reason anyone chose.

Measured against US-2 after the change (records visible inline):

    correlation_list_rules(500)      6 -> 50
    cloud_get_risks(500)             8 -> 48
    cloud_get_iom_detections(500)    4 -> 23
    cloud_query_assets(500)          7 -> 25
    spotlight_query_vulns(400)      36 -> 103

These tests pin: the budget is actually filled, the assembled response still fits
under the threshold it was cut to fit, and the pre-existing data-block semantics
survive.
"""

from crowdstrike_mcp.utils import (
    _NOTICE_RESERVE,
    _SUMMARY_MAX_LINES,
    LARGE_RESPONSE_THRESHOLD,
    _extract_summary,
    format_text_response,
)


def _record_lines(n, width=60):
    """n records rendered six lines each, the shape that exposed the old cap."""
    out = []
    for i in range(n):
        out += [
            f"{i + 1}. [ENABLED] Rule {i} {'x' * width}",
            f"   ID: id-{i}",
            "   Severity: 50",
            f"   Description: {'d' * width}",
            "   Updated: 2026-01-01",
            "",
        ]
    return out


class TestBudgetIsActuallyFilled:
    def test_summary_uses_most_of_the_budget(self):
        text = "\n".join(["Header line", ""] + _record_lines(500))
        summary = _extract_summary(text)
        budget = LARGE_RESPONSE_THRESHOLD - _NOTICE_RESERVE

        assert len(summary) <= budget
        # The old flat cap returned ~10% of the budget. Anything under half means
        # the budget is going unspent again.
        assert len(summary) > budget * 0.9

    def test_far_more_records_survive_than_the_old_line_cap(self):
        text = "\n".join(["Header line", ""] + _record_lines(500))
        old = _extract_summary(text, max_chars=10**9, max_lines=40)
        new = _extract_summary(text)

        # The old cap yielded a handful — 6 for the real correlation_list_rules
        # render; the exact number is a function of lines-per-record, so pin the
        # order of magnitude rather than this fixture's arithmetic.
        assert old.count("[ENABLED]") < 10
        assert new.count("[ENABLED]") > 40

    def test_verbose_and_terse_renderers_get_comparable_content(self):
        """The old cap gave a 1-line-per-record tool 6x the records of a
        6-line-per-record tool, purely as an artifact of the line count."""
        terse = "\n".join(f"{i}. record {'x' * 60}" for i in range(2000))
        verbose = "\n".join(_record_lines(500))

        terse_chars = len(_extract_summary(terse))
        verbose_chars = len(_extract_summary(verbose))

        assert abs(terse_chars - verbose_chars) < LARGE_RESPONSE_THRESHOLD * 0.1


class TestAssembledResponseStillFits:
    def test_notice_plus_summary_stays_under_the_threshold(self):
        text = "\n".join(["Header"] + _record_lines(500))
        out = format_text_response(
            text,
            tool_name="correlation_list_rules",
            raw=True,
            structured_data={"records": [{"id": f"r{i}", "name": "n", "description": "d" * 80} for i in range(500)]},
            metadata={"search": None},
        )
        assert "RESPONSE TRUNCATED" in out
        assert len(out) <= LARGE_RESPONSE_THRESHOLD, "the reserve is too small for the notice"

    def test_no_structured_data_path_also_fits(self):
        text = "\n".join(["Header"] + _record_lines(500))
        out = format_text_response(text, tool_name="some_tool", raw=True)
        assert len(out) <= LARGE_RESPONSE_THRESHOLD


class TestPreExistingSemanticsSurvive:
    def test_stops_at_the_second_data_block(self):
        text = "\n".join(["Header", "```json", '{"a": 1}', "```", "middle", "```json", '{"b": 2}', "```"])
        summary = _extract_summary(text)
        assert '{"a": 1}' in summary
        assert '{"b": 2}' not in summary

    def test_event_markers_still_bound_the_summary(self):
        text = "\n".join(["Header", "#### Event 1", "detail", "#### Event 2", "should not appear"])
        summary = _extract_summary(text)
        assert "#### Event 1" in summary
        assert "should not appear" not in summary

    def test_short_text_is_returned_whole(self):
        text = "line one\nline two\nline three"
        assert _extract_summary(text) == text


class TestEdgeCases:
    def test_single_oversized_line_still_yields_a_summary(self):
        """Taking at least one line means an oversized first line degrades to a
        long summary rather than an empty one."""
        text = "x" * (LARGE_RESPONSE_THRESHOLD * 2)
        assert _extract_summary(text) == text

    def test_line_ceiling_bounds_pathological_renders(self):
        """Thousands of near-empty lines fit in the byte budget; the secondary
        line bound keeps the result readable."""
        text = "\n".join("." for _ in range(50_000))
        summary = _extract_summary(text)
        assert len(summary.splitlines()) <= _SUMMARY_MAX_LINES

    def test_explicit_budget_is_honoured(self):
        text = "\n".join(f"line {i} {'x' * 50}" for i in range(1000))
        assert len(_extract_summary(text, max_chars=500)) <= 500
