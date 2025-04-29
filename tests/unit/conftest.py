"""Unit test fixtures for mcp-scan."""

import pytest


@pytest.fixture(params=["asyncio"])
def anyio_backend(request):
    return request.param


@pytest.fixture
def unit_test_fixture():
    """Fixture specific to unit tests."""
    return "unit_test_fixture_value"
