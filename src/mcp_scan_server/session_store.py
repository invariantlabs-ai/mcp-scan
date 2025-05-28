from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any


class MergeNodeTypes(Enum):
    SELF = "self"
    OTHER = "other"
    SELF_TO = "self_to"
    OTHER_TO = "other_to"


@dataclass(frozen=True)
class MergeInstruction:
    node_type: MergeNodeTypes
    index: int


@dataclass(frozen=True)
class SessionNode:
    """
    Represents a single event in a session.
    """

    timestamp: datetime
    message: dict[str, Any]
    session_id: str
    server_name: str
    original_session_index: int

    def __hash__(self) -> int:
        """Assume uniqueness by session_id, index in session and time of event."""
        return hash((self.session_id, self.original_session_index, self.timestamp))

    def __lt__(self, other: "SessionNode") -> bool:
        """Sort by timestamp."""
        return self.timestamp < other.timestamp


class Session:
    """
    Represents a sequence of SessionNodes, sorted by timestamp.
    """

    def __init__(
        self,
        nodes: list[SessionNode] | None = None,
    ):
        self.nodes: list[SessionNode] = nodes or []
        self.last_analysis_index: int = -1

    def _build_stack(self, other: "Session") -> list[MergeInstruction]:
        """
        Construct a build stack of the nodes that make up the merged session.

        The build stack is a list of instructions for how to construct the merged session.

        We iterate over the nodes of the two sessions in reverse order, essentially performing a
        heap merge. From this, we construct a set of instructions on how to construct the merged session.
        We could have built the merged sessions directly, but then we couldn't iterate in reverse order
        and thus not be able to exit early when we have found an already inserted node.
        """
        build_stack: list[MergeInstruction] = []
        ptr_self, ptr_other = len(self.nodes) - 1, len(other.nodes) - 1
        early_exit = False

        while ptr_self >= 0 and ptr_other >= 0:
            # Exit early if we have found an already inserted node.
            if self.nodes[ptr_self] == other.nodes[ptr_other]:
                build_stack.append(MergeInstruction(MergeNodeTypes.SELF_TO, ptr_self))
                early_exit = True
                break

            # Insert other node if it comes after the self node.
            elif self.nodes[ptr_self] < other.nodes[ptr_other]:
                build_stack.append(MergeInstruction(MergeNodeTypes.OTHER, ptr_other))
                ptr_other -= 1

            # Insert self node if it comes after the other node.
            else:
                build_stack.append(MergeInstruction(MergeNodeTypes.SELF, ptr_self))
                ptr_self -= 1

        # Handle remaining nodes in either self or other.
        # If we do not exit early, we should have some nodes
        # left in either self or other but not both.
        if not early_exit:
            if ptr_self >= 0:
                build_stack.append(MergeInstruction(MergeNodeTypes.SELF_TO, ptr_self))
            elif ptr_other >= 0:
                build_stack.append(MergeInstruction(MergeNodeTypes.OTHER_TO, ptr_other))

        return build_stack

    def _build_merged_nodes(self, build_stack: list[MergeInstruction], other: "Session") -> list[SessionNode]:
        """
        Build the merged nodes from the build stack.

        The build stack is a stack of instructions for how to construct the merged session.
        The node_type is either "self", "other", "self_to" or "other_to".
        The index is the index of the node in the session.
        The "self_to" and "other_to" tuples are used to indicate that all nodes up to and including the index should be inserted from the respective session.
        The "self" and "other" tuples are used to indicate that the node at the index should be inserted from the respective session.
        """
        merged_nodes = []
        for merged_index, instruction in enumerate(reversed(build_stack)):
            if instruction.node_type == MergeNodeTypes.SELF:
                merged_nodes.append(self.nodes[instruction.index])
            elif instruction.node_type == MergeNodeTypes.OTHER:
                merged_nodes.append(other.nodes[instruction.index])
                # Update the last analysis index to the index of the last node from other.
                self.last_analysis_index = min(self.last_analysis_index, merged_index)
            elif instruction.node_type == MergeNodeTypes.SELF_TO:
                merged_nodes.extend(self.nodes[: instruction.index + 1])
            elif instruction.node_type == MergeNodeTypes.OTHER_TO:
                merged_nodes.extend(other.nodes[: instruction.index + 1])
                # Reset the index because we have inserted nodes from other that
                # were before the nodes from self.
                self.last_analysis_index = -1
        return merged_nodes

    def merge(self, other: "Session") -> None:
        """
        Merge two session objects into a joint session.
        This assumes the precondition that both sessions are sorted and that duplicate nodes cannot exist
        (refer to the __hash__ method for session nodes).
        The postcondition is that the merged session is sorted, has no duplicates, and is the union of the two sessions.

        The algorithm proceeds in two steps:
          1. Construct a build stack of the nodes that make up the merged session.
          2. Iterate over the build stack in reverse order and build the merged nodes.

        When constructing the build stack, we can exit early if we have found an already inserted node
        using the precondition, since it implies that part of this trace has already been inserted --
        specifically the part before the equal nodes.
        """
        build_stack = self._build_stack(other)
        merged_nodes = self._build_merged_nodes(build_stack, other)
        self.nodes = merged_nodes

    def get_sorted_nodes(self) -> list[SessionNode]:
        return self.nodes

    def __repr__(self):
        return f"Session(nodes={self.get_sorted_nodes()})"


class SessionStore:
    """
    Stores sessions by client_name.
    """

    def __init__(self):
        self.sessions: dict[str, Session] = {}

    def _default_session(self) -> Session:
        return Session()

    def __str__(self):
        return f"SessionStore(sessions={self.sessions})"

    def __getitem__(self, client_name: str) -> Session:
        if client_name not in self.sessions:
            self.sessions[client_name] = self._default_session()
        return self.sessions[client_name]

    def __setitem__(self, client_name: str, session: Session) -> None:
        self.sessions[client_name] = session

    def __repr__(self):
        return self.__str__()

    def fetch_and_merge(self, client_name: str, other: Session) -> Session:
        """
        Fetch the session for the given client_name and merge it with the other session, returning the merged session.
        """
        session = self[client_name]
        session.merge(other)
        return session


async def to_session(messages: list[dict[str, Any]], server_name: str, session_id: str) -> Session:
    """
    Convert a list of messages to a session.
    """
    session_nodes: list[SessionNode] = []
    for i, message in enumerate(messages):
        timestamp = datetime.fromisoformat(message["timestamp"])
        session_nodes.append(
            SessionNode(
                server_name=server_name,
                message=message,
                original_session_index=i,
                session_id=session_id,
                timestamp=timestamp,
            )
        )

    return Session(nodes=session_nodes)
