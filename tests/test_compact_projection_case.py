"""The compact list projection must not depend on key casing.

The NGSIEM parsers endpoint returns ``Name`` and ``ID``; every other endpoint
returns ``name`` and ``id``. _COMPACT_LIST_FIELDS matched case-sensitively, so
every parser record projected to {} and ngsiem_list_parsers rendered:

    Parsers (2 results):
    #1:
    #2:

Two results, both blank — a count that is technically true and completely
useless. It was invisible before v5.9.0 (the call itself returned HTTP 400) and
invisible in the v5.9.0 verification, which exercised detail=True — and
detail=True skips this projection entirely. Compact is the DEFAULT path.
"""

from crowdstrike_mcp.modules.ngsiem import NGSIEMModule

PARSER = {
    "Name": "watchguard-firebox",
    "ID": "018bfba2b38a3734bf35cbc1fe4fffef:2.0.1",
    "current_version": "2.0.1",
    "parser_type": "ootb",
    "changelog": "x" * 400,
}

SAVED_QUERY = {"id": "q1", "name": "API Audit Query", "last_modified": "t", "body": "y" * 400}


class TestCaseInsensitiveProjection:
    def test_capitalised_keys_are_projected(self):
        (out,) = NGSIEMModule._project_compact([PARSER])
        assert out["Name"] == "watchguard-firebox"
        assert out["ID"].startswith("018bfba2")

    def test_projection_is_not_empty(self):
        """The actual regression: a blank record rendered as a blank entry."""
        (out,) = NGSIEMModule._project_compact([PARSER])
        assert out, "parser projected to an empty dict — renders as a blank entry"

    def test_bulk_fields_are_still_dropped(self):
        (out,) = NGSIEMModule._project_compact([PARSER])
        assert "changelog" not in out
        assert "current_version" not in out

    def test_lowercase_records_are_unaffected(self):
        (out,) = NGSIEMModule._project_compact([SAVED_QUERY])
        assert out == {"id": "q1", "name": "API Audit Query", "last_modified": "t"}

    def test_original_key_spelling_is_preserved(self):
        """Renaming keys in the projection would break callers reading them back."""
        (out,) = NGSIEMModule._project_compact([PARSER])
        assert "name" not in out and "id" not in out

    def test_canonical_field_order_is_kept(self):
        rec = {"status": "s", "name": "n", "id": "i"}
        (out,) = NGSIEMModule._project_compact([rec])
        assert list(out) == ["id", "name", "status"]


class TestFallbackForUnknownShapes:
    def test_record_matching_nothing_falls_through_whole(self):
        rec = {"alpha": 1, "beta": 2}
        (out,) = NGSIEMModule._project_compact([rec])
        assert out == rec, "an unmatched record must not render blank"

    def test_non_dict_records_pass_through(self):
        assert NGSIEMModule._project_compact(["cato-users.csv"]) == ["cato-users.csv"]

    def test_empty_input(self):
        assert NGSIEMModule._project_compact([]) == []
