"""Truncation notice carries a capped schema hint and a wildcard example."""

from crowdstrike_mcp.response_store import build_truncation_notice
from crowdstrike_mcp.utils import LARGE_RESPONSE_THRESHOLD, format_text_response


def _notice(data):
    return build_truncation_notice(
        summary="summary",
        text_len=50_000,
        ref_id="resp_001",
        record_count=2,
        tool_name="ngsiem_query",
        metadata={"query": "#type=x"},
        data=data,
    )


class TestNoticeSchemaHint:
    def test_fields_line_lists_paths(self):
        notice = _notice({"events": [{"id": 1, "event": {"ip": "1.1.1.1"}}]})
        assert "Fields: id, event.ip" in notice

    def test_fields_line_capped_with_more_suffix(self):
        record = {f"field_{i:03d}": i for i in range(60)}
        notice = _notice({"events": [record]})
        assert "Fields: " in notice
        assert "(+20 more)" in notice

    def test_no_fields_line_without_records(self):
        assert "Fields:" not in _notice({"events": []})
        assert "Fields:" not in _notice(None)

    def test_wildcard_example_present(self):
        notice = _notice({"events": [{"id": 1}]})
        assert 'fields="*"' in notice


class TestFormatTextResponsePassesData:
    def test_truncated_response_notice_includes_schema(self):
        data = {"events": [{"id": 1, "name": "x"}]}
        text = "line\n" * (LARGE_RESPONSE_THRESHOLD // 4)
        result = format_text_response(text, tool_name="ngsiem_query", raw=True, structured_data=data)
        assert "RESPONSE TRUNCATED" in result
        assert "Fields: id, name" in result
