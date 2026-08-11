"""Regression tests for the NGSIEM scoping params (issue #52).

Every NGSIEM content-management endpoint is scoped by a query param the API
requires and falconpy does not default. We never sent it, so seven tools failed
on every call — including their no-argument forms:

    ngsiem_list_lookup_files        HTTP 400 missing search_domain query param
    ngsiem_list_saved_queries       HTTP 400 missing search_domain query param
    ngsiem_list_dashboards          HTTP 400 missing search_domain query param
    ngsiem_get_saved_query_template HTTP 400 missing search_domain query param
    ngsiem_get_lookup_file          HTTP 400 missing search_domain / filename
    ngsiem_list_parsers             HTTP 400 missing repository query param
    ngsiem_get_parser               HTTP 400 missing repository query param

Verified against US-2 on 2026-08-11 — including the four the issue believed
were healthy. These tests pin the params onto the wire so a refactor that drops
one fails here instead of in production.
"""

import asyncio
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def ngsiem_module(mock_client):
    with patch("crowdstrike_mcp.modules.ngsiem.NGSIEM") as MockNGSIEM:
        mock_falcon = MagicMock()
        MockNGSIEM.return_value = mock_falcon
        from crowdstrike_mcp.modules.ngsiem import NGSIEMModule

        module = NGSIEMModule(mock_client)
        module._service = lambda cls: mock_falcon
        module.falcon = mock_falcon
        return module


def _ok(mock_method, resources=None):
    mock_method.return_value = {"status_code": 200, "body": {"resources": resources or []}}


class TestSearchDomainIsAlwaysSent:
    """The four search_domain-scoped tools."""

    @pytest.mark.parametrize(
        "tool_name,api_name",
        [
            ("ngsiem_list_lookup_files", "list_lookup_files"),
            ("ngsiem_list_saved_queries", "list_saved_queries"),
            ("ngsiem_list_dashboards", "list_dashboards"),
        ],
    )
    def test_list_tools_default_to_all(self, ngsiem_module, tool_name, api_name):
        api = getattr(ngsiem_module.falcon, api_name)
        _ok(api)
        asyncio.run(getattr(ngsiem_module, tool_name)())
        assert api.call_args.kwargs["search_domain"] == "all"

    @pytest.mark.parametrize(
        "tool_name,api_name",
        [
            ("ngsiem_list_lookup_files", "list_lookup_files"),
            ("ngsiem_list_saved_queries", "list_saved_queries"),
            ("ngsiem_list_dashboards", "list_dashboards"),
        ],
    )
    def test_list_tools_honour_an_explicit_domain(self, ngsiem_module, tool_name, api_name):
        api = getattr(ngsiem_module.falcon, api_name)
        _ok(api)
        asyncio.run(getattr(ngsiem_module, tool_name)(search_domain="third-party"))
        assert api.call_args.kwargs["search_domain"] == "third-party"

    def test_get_saved_query_template_sends_domain(self, ngsiem_module):
        _ok(ngsiem_module.falcon.get_saved_query_template, [{"id": "q1"}])
        asyncio.run(ngsiem_module.ngsiem_get_saved_query_template(id="q1"))
        kwargs = ngsiem_module.falcon.get_saved_query_template.call_args.kwargs
        assert kwargs["ids"] == "q1"
        assert kwargs["search_domain"] == "all"


class TestParsersUseRepositoryNotSearchDomain:
    """Parsers are scoped by `repository`, and the API takes exactly one value."""

    def test_list_parsers_sends_repository(self, ngsiem_module):
        _ok(ngsiem_module.falcon.list_parsers)
        asyncio.run(ngsiem_module.ngsiem_list_parsers())
        kwargs = ngsiem_module.falcon.list_parsers.call_args.kwargs
        assert kwargs["repository"] == "parsers-repository"
        assert "search_domain" not in kwargs

    def test_get_parser_sends_repository(self, ngsiem_module):
        _ok(ngsiem_module.falcon.get_parser, [{"id": "p1"}])
        asyncio.run(ngsiem_module.ngsiem_get_parser(id="p1"))
        kwargs = ngsiem_module.falcon.get_parser.call_args.kwargs
        assert kwargs["ids"] == "p1"
        assert kwargs["repository"] == "parsers-repository"


class TestFilterIsNormalizedToFQL:
    """These endpoints accept only name:~'value' and reject anything else."""

    def test_bare_substring_is_wrapped(self, ngsiem_module):
        _ok(ngsiem_module.falcon.list_lookup_files)
        asyncio.run(ngsiem_module.ngsiem_list_lookup_files(filter="cato"))
        assert ngsiem_module.falcon.list_lookup_files.call_args.kwargs["filter"] == "name:~'cato'"

    def test_existing_fql_is_passed_through(self, ngsiem_module):
        _ok(ngsiem_module.falcon.list_lookup_files)
        asyncio.run(ngsiem_module.ngsiem_list_lookup_files(filter="name:~'cato'"))
        assert ngsiem_module.falcon.list_lookup_files.call_args.kwargs["filter"] == "name:~'cato'"

    def test_quotes_in_a_bare_substring_cannot_break_the_literal(self, ngsiem_module):
        _ok(ngsiem_module.falcon.list_lookup_files)
        asyncio.run(ngsiem_module.ngsiem_list_lookup_files(filter="ca'to"))
        assert ngsiem_module.falcon.list_lookup_files.call_args.kwargs["filter"] == "name:~'cato'"

    def test_no_filter_sends_no_filter_key(self, ngsiem_module):
        _ok(ngsiem_module.falcon.list_lookup_files)
        asyncio.run(ngsiem_module.ngsiem_list_lookup_files())
        assert "filter" not in ngsiem_module.falcon.list_lookup_files.call_args.kwargs

    @pytest.mark.parametrize("blank", ["", "   ", None])
    def test_blank_filter_is_treated_as_absent(self, ngsiem_module, blank):
        assert ngsiem_module._as_name_fql(blank) is None


class TestDownloadResponsesDoNotCrash:
    def test_raw_bytes_response_is_unwrapped_not_an_attribute_error(self, ngsiem_module):
        """falconpy returns bytes for downloads — there is no status_code to read.

        _call_and_unwrap reads response.get() outside its try block, so a bytes
        response would surface as a server crash rather than a result.
        """
        result = ngsiem_module._call_and_unwrap(MagicMock(return_value=b"a,b\n1,2\n"), "get_lookup_file")
        assert result["success"] is True
        assert result["content"] == b"a,b\n1,2\n"
