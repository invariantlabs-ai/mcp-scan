import pytest
from mcp_scan.gateway import is_invariant_installed, MCPGatewayInstaller, MCPGatewayConfig
from mcp_scan.MCPScanner import scan_config_file
from tests.unit.test_mcp_client import SAMPLE_CONFIGS
import pyjson5
import tempfile
import os


@pytest.fixture
def temp_file():
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        yield tf.name
    os.remove(tf.name)

@pytest.mark.parametrize("server_config", SAMPLE_CONFIGS)
def test_install_gateway(server_config: str, temp_file):
    with open(temp_file, "w") as f:
        f.write(server_config)

    config_dict = pyjson5.loads(server_config)
    installer = MCPGatewayInstaller(paths=[temp_file])
    for server in scan_config_file(temp_file).get_servers().values():
        assert not is_invariant_installed(server)
    installer.install(gateway_config=MCPGatewayConfig(
        project_name="test",
        push_explorer=True,
        api_key="my-very-secret-api-key"
    ), verbose=True)
    config_dict_installed = pyjson5.loads(server_config)
    for server in scan_config_file(temp_file).get_servers().values():
        assert is_invariant_installed(server)
    installer.uninstall(verbose=True)
    mcp = scan_config_file(temp_file)
    for server in scan_config_file(temp_file).get_servers().values():
        assert not is_invariant_installed(server)

    config_dict_uninstalled = pyjson5.loads(server_config)
    
    assert config_dict_uninstalled == config_dict
