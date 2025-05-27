import heapq
from dataclasses import dataclass
from datetime import datetime
from typing import Any

Message = dict[str, Any]


@dataclass(frozen=True)
class SessionNode:
    """
    Represents a single event in a session.
    """

    timestamp: datetime
    message: Message
    session_id: str
    server_name: str
    original_session_index: int

    def __hash__(self) -> int:
        """Assume uniqueness by session_id, index in session and time of event."""
        return hash((self.session_id, self.original_session_index, self.timestamp))

    def __lt__(self, other: "SessionNode") -> bool:
        """Sort by timestamp."""
        return self.timestamp < other.timestamp

    def to_json(self) -> Message:
        """
        Convert the session node to a message.
        """
        return self.message


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
        self.last_pushed_index: int = -1

    def merge(self, other: "Session") -> None:
        """
        Merge two session objects into a joint session.
        This assumes the precondition that both sessions are sorted and has
        the postcondition that the merged session is sorted and has no duplicates.
        """
        merged_nodes = heapq.merge(self.nodes, other.nodes)
        combined_nodes: list[SessionNode] = []
        seen: set[SessionNode] = set()

        for node in merged_nodes:
            if node not in seen:
                seen.add(node)
                combined_nodes.append(node)
        self.nodes = combined_nodes

    def get_sorted_nodes(self) -> list[SessionNode]:
        return list(self.nodes)

    def __repr__(self):
        return f"Session(nodes={self.get_sorted_nodes()})"

    def to_json(self) -> list[Message]:
        """
        Convert the session to a list of messages.
        """
        return [node.to_json() for node in self.nodes]


class SessionStore:
    """
    Stores sessions by client_name.
    """

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.sessions = {}
        return cls._instance

    @classmethod
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

    def to_json(self) -> dict[str, dict[str, list[dict[str, Any]]]]:
        """
        Convert the sessions to a dictionary.
        """
        return {"sessions": {client_name: session.to_json() for client_name, session in self.sessions.items()}}

    def clear(self) -> None:
        """
        Clear the session store.
        """
        self.sessions: dict[str, Session] = {}


async def to_session(messages: list[Message], server_name: str, session_id: str) -> Session:
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
