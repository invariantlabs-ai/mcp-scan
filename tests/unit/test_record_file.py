import datetime
import json
import os
from unittest.mock import ANY, Mock

import pytest

from mcp_scan_server.record_file import (
    ExplorerRecordFile,
    LocalRecordFile,
    TraceClientMapping,
    parse_record_file_name,
    push_session_to_record_file,
)
from mcp_scan_server.session_store import Session, SessionNode, SessionStore


@pytest.fixture(autouse=True)
def cleanup_trace_client_mapping():
    """
    Cleanup the trace client mapping.
    """
    trace_client_mapping = TraceClientMapping()
    trace_client_mapping.clear()


@pytest.mark.parametrize("filename", ["explorer:test", "explorer:test", "explorer:test"])
def test_parse_record_filename_explorer_valid(filename, monkeypatch):
    monkeypatch.setattr("mcp_scan_server.record_file.Client", Mock())
    file = parse_record_file_name(filename)
    assert file.dataset_name == filename.split(":")[1]
    assert isinstance(file, ExplorerRecordFile)


@pytest.mark.parametrize("filename", ["local:test", "local:test"])
def test_parse_record_filename_local_valid(filename):
    file = parse_record_file_name(filename)
    assert isinstance(file, LocalRecordFile)


@pytest.mark.parametrize("filename", ["test.something", "test"])
def test_parse_record_filename_local_invalid(filename):
    with pytest.raises(ValueError):
        parse_record_file_name(filename)


def test_trace_client_mapping():
    """
    Test that we can set and get trace ids and client names.
    """
    trace_client_mapping = TraceClientMapping()
    trace_client_mapping.set_trace_id("trace_id", "client_name")
    trace_client_mapping.set_trace_id("trace_id_2", "client_name_2")

    # Test that the trace id and client name are correctly set
    assert trace_client_mapping.get_trace_id("client_name") == "trace_id"
    assert trace_client_mapping.get_client_name("trace_id") == "client_name"

    # test that non-existent trace ids return None
    assert trace_client_mapping.get_trace_id("client_name_3") is None
    assert trace_client_mapping.get_client_name("trace_id_3") is None

    # test that non-existent client names return None
    assert trace_client_mapping.get_trace_id("client_name_4") is None
    assert trace_client_mapping.get_client_name("trace_id_4") is None


def test_trace_client_mapping_shares_state():
    """
    Test that we maintain the same state across multiple instances of the TraceClientMapping class.
    """
    trace_ids = ["trace_id", "trace_id_2"]
    client_names = ["client_name", "client_name_2"]
    trace_client_mapping = TraceClientMapping()

    # Populate the first mapping
    for trace_id, client_name in zip(trace_ids, client_names, strict=False):
        trace_client_mapping.set_trace_id(trace_id, client_name)

    # Create a new mapping and check that the mappings are the same
    trace_client_mapping_2 = TraceClientMapping()
    for trace_id, client_name in zip(trace_ids, client_names, strict=False):
        assert trace_client_mapping_2.get_trace_id(client_name) == trace_id
        assert trace_client_mapping_2.get_client_name(trace_id) == client_name


def _setup_test_session_and_session_store():
    """Helper function to set up a test session."""
    # Create a session with a message
    session = Session(
        nodes=[
            SessionNode(
                timestamp=datetime.datetime.now(),
                message={"role": "user", "content": "test"},
                session_id="session_id",
                server_name="server_name",
                original_session_index=0,
            )
        ]
    )

    # Add the session to the session store
    session_store = SessionStore()
    session_store["client_name"] = session

    return session_store, session


def _setup_test_session_and_mock(monkeypatch, mock_trace_id="test_trace_id"):
    """Helper function to set up test session and mock client."""
    # Create a mock for the invariant SDK client
    mock_client = Mock()
    mock_client.create_request_and_push_trace.return_value = Mock(id=[mock_trace_id])

    monkeypatch.setattr("invariant_sdk.client.Client", mock_client)
    monkeypatch.setattr("mcp_scan_server.record_file.ExplorerRecordFile._check_is_key_set", Mock())

    # Create the trace client mapping
    trace_client_mapping = TraceClientMapping()

    return mock_client, trace_client_mapping


@pytest.mark.asyncio
async def test_push_session_to_record_file_explorer_first_time_calls_create_request_and_push_trace(monkeypatch):
    """
    Test that we call create_request_and_push_trace when pushing a session to the record file for the first time.
    """
    session_store, session = _setup_test_session_and_session_store()
    mock_client, trace_client_mapping = _setup_test_session_and_mock(monkeypatch)
    mock_trace_id = "test_trace_id"

    # Push the session to the record file
    trace_id = await push_session_to_record_file(
        session, ExplorerRecordFile("test", mock_client), "client_name", session_store
    )

    # Check that the trace id is set
    assert trace_id == mock_trace_id

    # Check that the trace id is in the trace client mapping
    assert trace_client_mapping.get_trace_id("client_name") == mock_trace_id

    # Check that the invariant sdk client was called with the correct arguments
    mock_client.create_request_and_push_trace.assert_called_once_with(
        messages=[[{"role": "user", "content": "test"}]],
        dataset="test",
        metadata=ANY,  # Ignore metadata
        annotations=ANY,
    )


@pytest.mark.asyncio
async def test_push_session_to_record_file_explorer_second_time_calls_append_messages(monkeypatch):
    """
    Test that we call append_messages when pushing a session to the record file for the second time.
    """
    session_store, session = _setup_test_session_and_session_store()
    mock_client, trace_client_mapping = _setup_test_session_and_mock(monkeypatch)
    mock_trace_id = "test_trace_id"
    message = {"role": "assistant", "content": "response"}

    # First push to set up the trace ID
    await push_session_to_record_file(session, ExplorerRecordFile("test", mock_client), "client_name", session_store)

    # Add a new message to the session
    session.nodes.append(
        SessionNode(
            timestamp=datetime.datetime.now(),
            message=message,
            session_id="session_id",
            server_name="server_name",
            original_session_index=1,
        )
    )
    # Second push should append
    trace_id = await push_session_to_record_file(
        session, ExplorerRecordFile("test", mock_client), "client_name", session_store
    )

    # Check that we got the same trace ID back
    assert trace_id == mock_trace_id

    # Check that the trace id is in the trace client mapping
    assert trace_client_mapping.get_trace_id("client_name") == mock_trace_id

    # Check that create_request_and_push_trace was only called once (from the first push)
    mock_client.create_request_and_push_trace.assert_called_once()

    # Check that append_messages was called with the correct arguments
    mock_client.create_request_and_append_messages.assert_called_once_with(
        messages=[message],
        trace_id=mock_trace_id,
        annotations=ANY,
    )


def _setup_test_session_and_local_file(tmp_path):
    """Helper function to set up test session and local file."""

    # Create the trace client mapping
    trace_client_mapping = TraceClientMapping()

    record_file = parse_record_file_name("local:test", base_path=str(tmp_path))
    assert isinstance(record_file, LocalRecordFile), "Should have LocalRecordFile"

    return trace_client_mapping, record_file


@pytest.mark.asyncio
async def test_push_session_to_record_file_local_creates_file_and_writes_to_it(tmp_path):
    """
    Test that we create a file and write to it when pushing a session to the record file for the first time.
    Also check that the path is set correctly to the LocalRecordFile data.
    """
    session_store, session = _setup_test_session_and_session_store()
    trace_client_mapping, record_file = _setup_test_session_and_local_file(tmp_path)

    # Push the session to the record file
    trace_id = await push_session_to_record_file(session, record_file, "client_name", session_store)

    # Check that the trace id is set
    assert trace_id is not None
    assert trace_client_mapping.get_trace_id("client_name") == trace_id

    # Check that the file was created with the correct path
    expected_path = record_file.get_session_file_path("client_name")
    assert os.path.exists(expected_path)

    # Check that the file contains the correct content
    with open(expected_path) as f:
        content = f.read().strip()
        assert content == json.dumps({"role": "user", "content": "test"})


@pytest.mark.asyncio
async def test_push_session_to_record_file_local_second_time_appends_to_file(tmp_path):
    """
    Test that we append to the file when pushing a session to the record file for the second time.
    """
    session_store, session = _setup_test_session_and_session_store()
    trace_client_mapping, record_file = _setup_test_session_and_local_file(tmp_path)

    # First push to set up the trace ID
    trace_id = await push_session_to_record_file(session, record_file, "client_name", session_store)

    # Add a new message to the session
    message = {"role": "assistant", "content": "response"}
    session.nodes.append(
        SessionNode(
            timestamp=datetime.datetime.now(),
            message=message,
            session_id="session_id",
            server_name="server_name",
            original_session_index=1,
        )
    )

    # Second push should append
    new_trace_id = await push_session_to_record_file(session, record_file, "client_name", session_store)

    # Check that we got the same trace ID back
    assert new_trace_id == trace_id

    # Check that the trace id is in the trace client mapping
    assert trace_client_mapping.get_trace_id("client_name") == new_trace_id

    # Check that the file contains both messages
    expected_path = record_file.get_session_file_path("client_name")
    with open(expected_path) as f:
        lines = [line.strip() for line in f.readlines() if line.strip()]  # Filter out empty lines
        assert len(lines) == 2
        assert json.loads(lines[0]) == {"role": "user", "content": "test"}
        assert json.loads(lines[1]) == message
