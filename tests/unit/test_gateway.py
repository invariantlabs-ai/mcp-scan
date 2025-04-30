import os
import tempfile

import pyjson5
import pytest
from pytest_lazy_fixtures import lf

from mcp_scan.gateway import MCPGatewayConfig, MCPGatewayInstaller, is_invariant_installed
from mcp_scan.mcp_client import scan_mcp_config_file
from mcp_scan.models import StdioServer


@pytest.fixture
def temp_file():
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        yield tf.name
    os.remove(tf.name)


@pytest.mark.parametrize("sample_config", [lf("claudestyle_config"), lf("vscode_mcp_config"), lf("vscode_config")])
def test_install_gateway(sample_config, temp_file):
    # TODO iterate over all sample configs
    with open(temp_file, "w") as f:
        f.write(sample_config)

    config_dict = pyjson5.loads(sample_config)
    installer = MCPGatewayInstaller(paths=[temp_file])
    for server in scan_mcp_config_file(temp_file).get_servers().values():
        if isinstance(server, StdioServer):
            assert not is_invariant_installed(server), "Invariant should not be installed"
    installer.install(
        gateway_config=MCPGatewayConfig(project_name="test", push_explorer=True, api_key="my-very-secret-api-key"),
        verbose=True,
    )

    # try to load the config
    pyjson5.loads(sample_config)

    for server in scan_mcp_config_file(temp_file).get_servers().values():
        if isinstance(server, StdioServer):
            assert is_invariant_installed(server), "Invariant should be installed"

    installer.uninstall(verbose=True)

    for server in scan_mcp_config_file(temp_file).get_servers().values():
        if isinstance(server, StdioServer):
            assert not is_invariant_installed(server), "Invariant should be uninstalled"

    config_dict_uninstalled = pyjson5.loads(sample_config)

    assert (
        config_dict_uninstalled == config_dict
    ), "Installation and uninstallation of the gateway should not change the config file"
