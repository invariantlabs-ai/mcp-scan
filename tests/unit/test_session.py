import datetime

import pytest

from src.mcp_scan_server.session_store import Session, SessionNode, SessionStore, to_session


def create_timestamped_node(timestamp: datetime.datetime):
    return SessionNode(timestamp=timestamp, message={}, session_id="", server_name="", original_session_index=0)


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


def test_session_merge_empty_self():
    node_session2 = create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, 0))
    session1 = Session(nodes=[])
    session2 = Session(nodes=[node_session2])
    session1.merge(session2)
    assert session1.nodes == [node_session2]


def test_session_merge_empty_other():
    node_session1 = create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, 0))
    session1 = Session(nodes=[node_session1])
    session2 = Session(nodes=[])
    session1.merge(session2)
    assert session1.nodes == [node_session1]


def test_session_merge_empty_self_and_other():
    session1 = Session(nodes=[])
    session2 = Session(nodes=[])
    session1.merge(session2)
    assert session1.nodes == []


def test_session_merge_self_is_same_as_other():
    """
    When the self session is the same as the other session, we should not change the self session.
    """
    nodes_session1 = [
        create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, 0)),
        create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, 1)),
    ]
    session1 = Session(nodes=nodes_session1)
    session2 = Session(nodes=nodes_session1)
    session1.merge(session2)
    assert session1.nodes == nodes_session1


def test_session_merge_self_is_prefix_of_other():
    """
    When the self session is a prefix of the other session, we should only insert the difference.
    """
    nodes1 = [
        create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, 0)),
        create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, 1)),
    ]
    nodes2 = [
        nodes1[0],
        nodes1[1],
        create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, 2)),
    ]
    session1 = Session(nodes=nodes1)
    session2 = Session(nodes=nodes2)
    session1.merge(session2)
    assert len(session1.nodes) == 3
    assert session1.nodes == nodes2


def test_session_merge_self_is_in_middle_of_other():
    """ """
    nodes1 = [
        create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, 0)),
        create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, 3)),
    ]

    nodes2 = [
        create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, 1)),
        create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, 2)),
    ]
    session1 = Session(nodes=nodes1)
    session2 = Session(nodes=nodes2)
    session1.merge(session2)
    assert len(session1.nodes) == 4
    assert session1.nodes == [
        nodes1[0],
        nodes2[0],
        nodes2[1],
        nodes1[1],
    ]


def test_session_merge_self_is_subset_of_other():
    nodes1 = [
        create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, 0)),
        create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, 1)),
        create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, 2)),
        create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, 3)),
    ]
    nodes2 = [
        nodes1[1],
        nodes1[2],
    ]
    session1 = Session(nodes=nodes1)
    session2 = Session(nodes=nodes2)
    session1.merge(session2)
    assert len(session1.nodes) == 4
    assert session1.nodes == nodes1


def test_session_merge_overlapping_sessions():
    """Test merging sessions that partially overlap but neither is a subset."""
    nodes1 = [
        create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, 0)),
        create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, 1)),
        create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, 4)),
    ]
    nodes2 = [
        create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, 1)),  # shared
        create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, 2)),
        create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, 3)),
    ]
    session1 = Session(nodes=nodes1)
    session2 = Session(nodes=nodes2)
    session1.merge(session2)

    expected = [nodes1[0], nodes1[1], nodes2[1], nodes2[2], nodes1[2]]
    assert session1.nodes == expected


def test_session_merge_disjoint_sessions():
    """Test merging sessions with no overlapping nodes."""
    nodes1 = [
        create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, 0)),
        create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, 1)),
    ]
    nodes2 = [
        create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, 2)),
        create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, 3)),
    ]
    session1 = Session(nodes=nodes1)
    session2 = Session(nodes=nodes2)
    session1.merge(session2)

    assert len(session1.nodes) == 4
    assert session1.nodes == nodes1 + nodes2


def test_session_merge_single_nodes():
    """Test merging sessions with single nodes."""
    node1 = create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, 0))
    node2 = create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, 1))

    session1 = Session(nodes=[node1])
    session2 = Session(nodes=[node2])
    session1.merge(session2)

    assert session1.nodes == [node1, node2]


def test_session_merge_maintains_chronological_order():
    """Verify that merged sessions are always in chronological order."""
    nodes1 = [create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, i)) for i in [0, 3, 6, 9]]
    nodes2 = [create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, i)) for i in [1, 4, 7, 10]]

    session1 = Session(nodes=nodes1)
    session2 = Session(nodes=nodes2)
    session1.merge(session2)

    # Verify chronological order
    for i in range(len(session1.nodes) - 1):
        assert session1.nodes[i].timestamp <= session1.nodes[i + 1].timestamp


def test_session_merge_last_analysis_index_maintained_on_insert_after():
    """
    Check that `last_analysis_index` is not updated when we merge nodes from
    "other" that are all after the last analysis index.
    """
    nodes1 = [
        create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, 0)),
        create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, 1)),
    ]
    nodes2 = [
        create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, 2)),
    ]

    session1 = Session(nodes=nodes1)
    session1.last_analysis_index = 1
    print(session1.last_analysis_index)

    session2 = Session(nodes=nodes2)
    session1.merge(session2)
    assert session1.last_analysis_index == 1


def test_session_merge_last_analysis_index_is_updated_on_insert_before():
    """
    Check that `last_analysis_index` is updated when we merge nodes from
    "other" that has nodes before the last analysis index.
    """
    nodes1 = [
        create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, 0)),
        create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, 1)),
        create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, 3)),
        create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, 4)),
    ]
    nodes2 = [
        create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, 2)),
    ]

    session1 = Session(nodes=nodes1)
    session1.last_analysis_index = 3

    session2 = Session(nodes=nodes2)
    session1.merge(session2)
    assert session1.last_analysis_index == 1


def test_session_merge_last_analysis_index_is_updated_on_insert_before_and_after():
    """
    Check that `last_analysis_index` is updated when we merge nodes from
    "other" that has nodes before and after the last analysis index. We should
    see that the new last_analysis_index is the index of the oldest node from "other".
    """
    nodes1 = [
        create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, 0)),
        create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, 1)),
        create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, 2)),
        create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, 4)),
    ]
    nodes2 = [
        create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, 3)),
        create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, 5)),
    ]

    session1 = Session(nodes=nodes1)
    session1.last_analysis_index = 4

    session2 = Session(nodes=nodes2)
    session1.merge(session2)
    assert session1.last_analysis_index == 1


def test_session_merge_last_analysis_index_is_reset_when_other_has_nodes_before_self():
    """
    Check that `last_analysis_index` is reset when we merge nodes from
    "other" that has nodes before the last analysis index.
    """
    nodes1 = [
        create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, 2)),
        create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, 4)),
    ]

    nodes2 = [
        create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, 0)),
        create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, 1)),
        create_timestamped_node(datetime.datetime(2021, 1, 1, 12, 0, 3)),
    ]

    session1 = Session(nodes=nodes1)
    session1.last_analysis_index = 2

    session2 = Session(nodes=nodes2)
    session1.merge(session2)
    assert session1.last_analysis_index == -1
