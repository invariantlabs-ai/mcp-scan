import datetime
import json

import pytest

from src.mcp_scan_server.session_store import Session, SessionNode, SessionStore, to_session


def create_timestamped_node(timestamp: datetime.datetime):
    return SessionNode(timestamp=timestamp, message={}, session_id="", server_name="", original_session_index=0)


# create a cleanup function to delete the session store and make it run after each test
def cleanup_session_store():
    session_store = SessionStore()
    session_store.clear()


@pytest.fixture(autouse=True)
def cleanup_session_store_after_test():
    yield
    cleanup_session_store()


@pytest.fixture
def some_date():
    return datetime.datetime(2021, 1, 1, 12, 0, 0)


def test_session_node_ordering(some_date: datetime.datetime):
    """Make sure session nodes are sorted by timestamp"""
    session_nodes = [
        create_timestamped_node(some_date),
        create_timestamped_node(some_date - datetime.timedelta(seconds=1)),
        create_timestamped_node(some_date - datetime.timedelta(seconds=2)),
    ]
    session_nodes.sort()
    assert session_nodes[0].timestamp < session_nodes[1].timestamp
    assert session_nodes[1].timestamp < session_nodes[2].timestamp


def test_session_class_merge_function_ignore_duplicates(some_date: datetime.datetime):
    session1_nodes = [
        create_timestamped_node(some_date),
        create_timestamped_node(some_date + datetime.timedelta(seconds=1)),
        create_timestamped_node(some_date + datetime.timedelta(seconds=2)),  # duplicate node
    ]
    session2_nodes = [
        create_timestamped_node(some_date + datetime.timedelta(seconds=2)),  # duplicate node
        create_timestamped_node(some_date + datetime.timedelta(seconds=3)),
    ]
    session1 = Session(nodes=session1_nodes)
    session2 = Session(nodes=session2_nodes)

    # Check that the nodes are sorted (precondition for merge)
    assert session1_nodes == session1.nodes
    assert session2_nodes == session2.nodes

    session1.merge(session2)

    # Check that duplicate is ignored
    assert len(session1.nodes) == 4, "Duplicate nodes should be ignored"

    # Check that the nodes are sorted and dates are correct
    assert session1.nodes[0].timestamp == some_date
    assert session1.nodes[1].timestamp == some_date + datetime.timedelta(seconds=1)
    assert session1.nodes[2].timestamp == some_date + datetime.timedelta(seconds=2)
    assert session1.nodes[3].timestamp == some_date + datetime.timedelta(seconds=3)


def test_session_store_missing_client_name(some_date: datetime.datetime):
    """Test that the session store returns a default session if the client name is not found"""
    session_store = SessionStore()
    session_store["client_name"] = Session(nodes=[])
    assert session_store["client_name"] is not None

    # Check that the default session is returned if the client name is not found
    assert session_store["missing_client_name"] is not None
    assert session_store["missing_client_name"].nodes == []


def test_session_store_fetch_and_merge_only_relevant_sessions_is_updated(some_date: datetime.datetime):
    session_store = SessionStore()

    # Create two clients with some nodes
    client1_nodes = [
        create_timestamped_node(some_date),
        create_timestamped_node(some_date + datetime.timedelta(seconds=1)),
    ]
    client2_nodes = [
        create_timestamped_node(some_date + datetime.timedelta(seconds=2)),
        create_timestamped_node(some_date + datetime.timedelta(seconds=3)),
    ]

    # Add the clients to the session store
    session_store["client_name_1"] = Session(nodes=client1_nodes)
    session_store["client_name_2"] = Session(nodes=client2_nodes)

    # Create new nodes for client 1
    new_nodes = [
        create_timestamped_node(some_date + datetime.timedelta(seconds=4)),
        create_timestamped_node(some_date + datetime.timedelta(seconds=5)),
    ]
    new_nodes_session = Session(nodes=new_nodes)

    session_store.fetch_and_merge("client_name_1", new_nodes_session)

    # Check that the new nodes are merged with the old nodes
    assert session_store["client_name_1"].nodes == [
        client1_nodes[0],
        client1_nodes[1],
        new_nodes[0],
        new_nodes[1],
    ]

    # Check that the other client's session is not affected
    assert session_store["client_name_2"].nodes == client2_nodes


@pytest.mark.asyncio
async def test_original_session_index_server_name_and_session_id_are_maintained_during_merge():
    session_nodes = [
        {"role": "user", "content": "msg1", "timestamp": "2021-01-01T12:00:00Z"},
        {"role": "assistant", "content": "msg2", "timestamp": "2021-01-01T12:00:01Z"},
    ]
    server1_name = "server_name1"
    session_id1 = "session_id1"
    session = await to_session(session_nodes, server1_name, session_id1)
    assert session.nodes[0].original_session_index == 0
    assert session.nodes[1].original_session_index == 1

    new_nodes = [
        {"role": "user", "content": "msg1", "timestamp": "2021-01-01T12:00:02Z"},
        {"role": "assistant", "content": "msg2", "timestamp": "2021-01-01T12:00:03Z"},
    ]
    server2_name = "server_name2"
    session_id2 = "session_id2"
    new_nodes_session = await to_session(new_nodes, server2_name, session_id2)
    session.merge(new_nodes_session)

    # Assert original session index is maintained
    assert session.nodes[0].original_session_index == 0
    assert session.nodes[1].original_session_index == 1
    assert session.nodes[2].original_session_index == 0
    assert session.nodes[3].original_session_index == 1

    # Assert server name and session id are maintained
    assert session.nodes[0].server_name == server1_name
    assert session.nodes[1].server_name == server1_name

    assert session.nodes[2].server_name == server2_name
    assert session.nodes[3].server_name == server2_name

    assert session.nodes[0].session_id == session_id1
    assert session.nodes[1].session_id == session_id1

    assert session.nodes[2].session_id == session_id2
    assert session.nodes[3].session_id == session_id2


@pytest.mark.asyncio
async def test_to_session_function():
    """Test that the to_session function creates a session with the correct nodes"""
    messages = [
        {"role": "user", "content": "Hello, world!", "timestamp": "2021-01-01T12:00:00Z"},
        {"role": "assistant", "content": "Hello, world!", "timestamp": "2021-01-01T12:00:01Z"},
    ]
    session = await to_session(messages, "server_name", "session_id")
    assert session.nodes == [
        SessionNode(
            timestamp=datetime.datetime.fromisoformat(messages[0]["timestamp"]),
            message=messages[0],
            session_id="session_id",
            server_name="server_name",
            original_session_index=0,
        ),
        SessionNode(
            timestamp=datetime.datetime.fromisoformat(messages[1]["timestamp"]),
            message=messages[1],
            session_id="session_id",
            server_name="server_name",
            original_session_index=1,
        ),
    ]


def test_session_node_to_json():
    session_node = SessionNode(
        timestamp=datetime.datetime.now(),
        message={"role": "user", "content": "Hello, world!"},
        session_id="session_id",
        server_name="server_name",
        original_session_index=0,
    )

    session = Session(nodes=[session_node])

    session_store = SessionStore()
    session_store["client_name"] = session

    session_store_json = session_store.to_json()
    assert session_store_json is not None


def test_json_serialization():
    """Test that the JSON serialization works correctly for all classes."""
    timestamp = datetime.datetime(2024, 1, 1, 12, 0, 0)
    message = {"role": "user", "content": "Hello, world!"}

    # Create a session node
    node = SessionNode(
        timestamp=timestamp,
        message=message,
        session_id="test_session",
        server_name="test_server",
        original_session_index=0,
    )

    # Test SessionNode JSON serialization
    node_dict = node.to_json()
    assert node_dict == message

    # Create a session with the node
    session = Session(nodes=[node])

    # Test Session JSON serialization
    session_dict = session.to_json()
    assert session_dict == [message]

    # Create a session store with the session
    store = SessionStore()
    store["test_client"] = session

    # Test SessionStore JSON serialization
    store_json = store.to_json()
    assert store_json == {"sessions": {"test_client": [message]}}

    # Finally test that we can dump and load
    store_json_str = json.dumps(store_json)
    assert store_json_str is not None

    store_dict = json.loads(store_json_str)
    assert store_dict == {"sessions": {"test_client": [message]}}


def test_session_store_shares_state():
    """Test that the session store shares state between multiple instances."""

    # Create and populate the session store
    session_store = SessionStore()
    session_store["client_name_1"] = Session(
        nodes=[
            SessionNode(
                timestamp=datetime.datetime.now(),
                message={"role": "user", "content": "Hello, world!"},
                session_id="session_id",
                server_name="server_name",
                original_session_index=0,
            )
        ]
    )

    # Create new session store and check that the session is shared
    session_store_2 = SessionStore()
    assert session_store_2["client_name_1"] is not None
    assert session_store_2["client_name_1"].nodes == session_store["client_name_1"].nodes
