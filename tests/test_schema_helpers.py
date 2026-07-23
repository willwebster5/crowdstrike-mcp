"""Tests for shared schema helpers in response_store.py."""

from crowdstrike_mcp.response_store import (
    format_fields_line,
    metadata_context,
    schema_hint,
    top_level_keys,
)


class TestTopLevelKeys:
    def test_union_preserving_first_seen_order(self):
        records = [{"b": 1, "a": 2}, {"a": 3, "c": 4}, "not-a-dict"]
        assert top_level_keys(records) == ["b", "a", "c"]

    def test_empty(self):
        assert top_level_keys([]) == []


class TestSchemaHint:
    def test_nested_dicts_expand_one_level(self):
        records = [{"id": 1, "event": {"ip": "1.2.3.4", "user": "x"}}]
        assert schema_hint(records) == ["id", "event.ip", "event.user"]

    def test_flat_records(self):
        assert schema_hint([{"a": 1, "b": 2}]) == ["a", "b"]


class TestFormatFieldsLine:
    def test_under_caps_joins_all(self):
        assert format_fields_line(["a", "b"]) == "a, b"

    def test_entry_cap_appends_more_suffix(self):
        entries = [f"field_{i}" for i in range(50)]
        line = format_fields_line(entries, max_entries=40)
        assert "field_39" in line
        assert "field_40" not in line
        assert "(+10 more)" in line

    def test_char_cap_applies_before_entry_cap(self):
        entries = [f"very_long_field_name_number_{i:04d}" for i in range(40)]
        line = format_fields_line(entries, max_chars=100)
        assert len(line) <= 100 + len(" (+XX more)") + 4
        assert "more)" in line

    def test_empty_entries(self):
        assert format_fields_line([]) == ""


class TestMetadataContext:
    def test_picks_first_context_key(self):
        assert metadata_context({"query": "#type=x | tail(5)"}) == "query: #type=x | tail(5)"

    def test_detection_id_beats_query(self):
        md = {"query": "q", "detection_id": "abc:123"}
        assert metadata_context(md) == "detection_id: abc:123"

    def test_empty_metadata(self):
        assert metadata_context({}) == ""
        assert metadata_context(None) == ""

    def test_multiline_query_flattened_to_one_line(self):
        md = {"query": "#type=x\n| tail(5)\n  | table(a, b)"}
        result = metadata_context(md)
        assert "\n" in md["query"]  # sanity: input actually has newlines
        assert "\n" not in result
        assert "  " not in result

    def test_long_query_capped_with_ellipsis(self):
        md = {"query": "a" * 500}
        result = metadata_context(md)
        assert result.startswith("query: ")
        assert result == f"query: {'a' * 200}…"
        assert len(result) == len("query: ") + 201
