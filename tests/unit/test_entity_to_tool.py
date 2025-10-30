import pytest

from mcp_scan.models import ServerSignature, entity_to_tool


@pytest.mark.parametrize(
    "signature_file_path",
    [
        "tests/mcp_servers/signatures/math_server_signature.json",
        "tests/mcp_servers/signatures/weather_server_signature.json",
    ],
)
def test_entity_to_tool(signature_file_path):
    with open(signature_file_path) as f:
        signature = ServerSignature.model_validate_json(f.read())
    for entity in signature.entities:
        _ = entity_to_tool(entity)
