import os
import tempfile

import pyjson5
import pytest

from mcp_scan.gateway import MCPGatewayConfig, MCPGatewayInstaller, is_invariant_installed
from mcp_scan.MCPScanner import scan_mcp_config_file
from mcp_scan.models import StdioServer
from tests.unit.test_mcp_client import SAMPLE_CONFIGS


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
    for server in scan_mcp_config_file(temp_file).get_servers().values():
        if isinstance(server, StdioServer):
            assert not is_invariant_installed(server), "Invariant should not be installed"
    installer.install(
        gateway_config=MCPGatewayConfig(project_name="test", push_explorer=True, api_key="my-very-secret-api-key"),
        verbose=True,
    )

    # try to load the config
    pyjson5.loads(server_config)

    for server in scan_mcp_config_file(temp_file).get_servers().values():
        if isinstance(server, StdioServer):
            assert is_invariant_installed(server), "Invariant should be installed"

    installer.uninstall(verbose=True)

    for server in scan_mcp_config_file(temp_file).get_servers().values():
        if isinstance(server, StdioServer):
            assert not is_invariant_installed(server), "Invariant should be uninstalled"

    config_dict_uninstalled = pyjson5.loads(server_config)

    assert (
        config_dict_uninstalled == config_dict
    ), "Installation and uninstallation of the gateway should not change the config file"
