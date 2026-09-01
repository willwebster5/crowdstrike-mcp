"""Regression test pinning the wire format of case_upload_file's multipart request.

falconpy 1.6.1's CaseManagement.upload_file() sent `case_id` and `description`
as URL query-string parameters instead of multipart form-data fields, even
though the /case-files/entities/files/upload/v1 endpoint only reads them from
the form body. The CrowdStrike API then 404'd because it saw no case_id in
the multipart body. Fixed upstream in falconpy 1.6.2. This test exercises the
*real* falconpy client (only the network call is mocked) so a regression to
an unpatched falconpy version fails loudly here instead of as a live 404.
"""

from unittest.mock import patch

from falconpy import CaseManagement

from crowdstrike_mcp.modules.case_management import CaseManagementModule


class _FakeResponse:
    status_code = 201
    headers = {"content-type": "application/json"}
    content = b"{}"

    def json(self):
        return {}


def test_upload_file_sends_case_id_and_description_as_form_data(mock_client, tmp_path):
    f = tmp_path / "report.md"
    f.write_text("hunt report contents")

    captured = {}

    def fake_request(method, url, **kwargs):
        captured["method"] = method
        captured["url"] = url
        captured.update(kwargs)
        return _FakeResponse()

    real_falcon = CaseManagement(access_token="fake-token")
    module = CaseManagementModule(mock_client)
    module._service = lambda cls: real_falcon

    with patch("requests.request", side_effect=fake_request):
        result = module._upload_file(
            case_id="01a0592c-7535-74ab-ae7a-55d4a9ab7904",
            file_path=str(f),
            description="hunt report",
        )

    assert result["success"] is True
    # case_id and description are formData fields per the API's swagger doc —
    # they must travel in the multipart body, not the query string.
    data = captured.get("data") or {}
    assert data.get("case_id") == "01a0592c-7535-74ab-ae7a-55d4a9ab7904"
    assert data.get("description") == "hunt report"
    params = captured.get("params") or {}
    assert "case_id" not in params
