import json

import pyjson5
import pytest
from pytest_lazy_fixtures import lf

from mcp_scan.gateway import MCPGatewayConfig, MCPGatewayInstaller, is_invariant_installed
from mcp_scan.mcp_client import scan_mcp_config_file
from mcp_scan.models import StdioServer


@pytest.mark.asyncio
@pytest.mark.parametrize("sample_config_file", [lf("claudestyle_config_file")])
async def test_install_gateway(sample_config_file):
    with open(sample_config_file) as f:
        config_dict = pyjson5.load(f)
    installer = MCPGatewayInstaller(paths=[sample_config_file])
    for server in (await scan_mcp_config_file(sample_config_file)).get_servers().values():
        if isinstance(server, StdioServer):
            assert not is_invariant_installed(server), "Invariant should not be installed"
    await installer.install(
        gateway_config=MCPGatewayConfig(project_name="test", push_explorer=True, api_key="my-very-secret-api-key"),
        verbose=True,
    )

    # try to load the config
    with open(sample_config_file) as f:
        pyjson5.load(f)

    for server in (await scan_mcp_config_file(sample_config_file)).get_servers().values():
        if isinstance(server, StdioServer):
            assert is_invariant_installed(server), "Invariant should be installed"

    await installer.uninstall(verbose=True)

    for server in (await scan_mcp_config_file(sample_config_file)).get_servers().values():
        if isinstance(server, StdioServer):
            assert not is_invariant_installed(server), "Invariant should be uninstalled"

    with open(sample_config_file) as f:
        config_dict_uninstalled = pyjson5.load(f)

    # check for mcpServers.<object>.type and remove it if it exists (we are fine if it is added after install/uninstall)
    for server in config_dict_uninstalled.get("mcpServers", {}).values():
        if "type" in server:
            del server["type"]

    # compare the config files
    assert json.dumps(config_dict, sort_keys=True) == json.dumps(config_dict_uninstalled, sort_keys=True), (
        "Installation and uninstallation of the gateway should not change the config file" + f" {sample_config_file}.\n"
        f"Original config: {config_dict}\n" + f"Uninstalled config: {config_dict_uninstalled}\n"
    )
