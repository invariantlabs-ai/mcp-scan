import json
import os
import uuid
from dataclasses import dataclass

import rich
from invariant_sdk.client import Client

from .session_store import Message, Session, SessionStore


class TraceClientMapping:
    """
    A singleton class to store the mapping between trace ids and client names.

    This is used to ensure that a trace id is generated only once for a given client and
    that it is consistent, so we can append to explorer properly.
    """

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.trace_id_to_client_name = {}
            cls._instance.client_name_to_trace_id = {}
        return cls._instance

    def get_client_name(self, trace_id: str) -> str | None:
        """
        Get the client name for the given trace id.
        """
        return self.trace_id_to_client_name.get(trace_id, None)

    def get_trace_id(self, client_name: str) -> str | None:
        """
        Get the trace id for the given client name.
        """
        return self.client_name_to_trace_id.get(client_name, None)

    def set_trace_id(self, trace_id: str, client_name: str) -> None:
        """
        Set the trace id for the given client name.
        """
        self.trace_id_to_client_name[trace_id] = client_name
        self.client_name_to_trace_id[client_name] = trace_id

    def clear(self) -> None:
        """
        Clear the trace client mapping.
        """
        self.trace_id_to_client_name: dict[str, str] = {}
        self.client_name_to_trace_id: dict[str, str] = {}

    def __str__(self) -> str:
        return f"TraceClientMapping[{self.trace_id_to_client_name}]"

    def __repr__(self) -> str:
        return self.__str__()


def generate_record_file_postfix() -> str:
    """Generate a random postfix for the record file."""
    return str(uuid.uuid4())[:8]


# Initialize the invariant sdk client if the API key is set
invariant_sdk_client = Client() if os.environ.get("INVARIANT_API_KEY") else None

# Initialize the trace client mapping and session store
trace_client_mapping = TraceClientMapping()
session_store = SessionStore()
record_post_fix = generate_record_file_postfix()


@dataclass(frozen=True)
class RecordFile:
    """Base class for record file names."""

    def __message_styling_wrapper__(self, message: str) -> str:
        """Wrap the message in styling."""
        return f"[yellow]Recording session data to {message}[/yellow]"

    def startup_message(self) -> str:
        """Return a message to be printed on startup."""
        raise NotImplementedError("Subclasses must implement this method")


@dataclass(frozen=True)
class ExplorerRecordFile(RecordFile):
    """Record file for explorer datasets."""

    dataset_name: str

    def startup_message(self) -> str:
        """Return a message to be printed on startup."""
        return self.__message_styling_wrapper__(f"explorer dataset: '{self.dataset_name}'")


@dataclass(frozen=True)
class LocalRecordFile(RecordFile):
    """Record file for local files."""

    filename: str
    base_path: str = os.path.expanduser("~/.mcp-scan/sessions")
    postfix: str = ""

    def startup_message(self) -> str:
        """Return a message to be printed on startup."""
        return self.__message_styling_wrapper__(f"local file: '{os.path.join(self.base_path, self.filename)}'")

    def get_session_file_path(self, client_name: str | None) -> str:
        """Get the path to the session file for a given client."""
        # Use client name as the filename, with .jsonl extension
        client_name = client_name or "unknown"
        return os.path.join(self.base_path, f"{client_name}-{self.postfix}.jsonl")


def parse_record_file_name(record_file: str | None) -> RecordFile | None:
    """Parse the record file name and return a RecordFile object."""
    if record_file is None:
        return None

    # Check if it has the form explorer:{dataset_name}
    if record_file.startswith("explorer:"):
        dataset_name = record_file.split(":")[1]
        return ExplorerRecordFile(dataset_name)

    # Check that it ends with .json or .jsonl
    if not record_file.endswith(".json") and not record_file.endswith(".jsonl"):
        raise ValueError(f"Record file must end with .json or .jsonl: {record_file}")

    return LocalRecordFile(record_file, postfix=record_post_fix)


async def _push_session_to_explorer(
    session_data: list[Message], record_file: ExplorerRecordFile, client_name: str
) -> str | None:
    """
    Push the session to the explorer.
    """
    if invariant_sdk_client is None:
        raise ValueError(
            "Invariant SDK client is not initialized. Please set the INVARIANT_API_KEY environment variable."
        )

    try:
        response = invariant_sdk_client.create_request_and_push_trace(
            messages=[session_data],
            dataset=record_file.dataset_name,
            metadata=[
                {
                    "hierarchy_path": [client_name],
                }
            ],
        )

        trace_id = response.id[0]
        trace_client_mapping.set_trace_id(trace_id, client_name)
        return trace_id
    except Exception as e:
        rich.print(f"[bold red]Error pushing session to explorer: {e}[/bold red]")
        return None


async def _push_session_to_local_file(
    session_data: list[Message], record_file: LocalRecordFile, client_name: str
) -> str | None:
    """
    Push the session to the local file.
    """
    os.makedirs(record_file.base_path, exist_ok=True)
    trace_id = str(uuid.uuid4())
    trace_client_mapping.set_trace_id(trace_id, client_name)

    session_file_path = record_file.get_session_file_path(client_name)

    # Write each message as a JSONL line
    with open(session_file_path, "a") as f:
        for message in session_data:
            f.write(json.dumps(message) + "\n")

    return trace_id


async def _format_session_data(session: Session, index: int) -> list[Message]:
    """
    Format the session data for the record file.
    Only returns new messages that haven't been recorded yet.
    """
    # convert session data to a list of messages, but only include new ones
    messages = []
    for i, node in enumerate(session.nodes):
        if i > index:
            messages.append(node.message)

    return messages


async def _append_messages_to_explorer(
    trace_id: str, session_data: list[Message], record_file: ExplorerRecordFile
) -> None:
    """
    Append messages to the explorer.
    """
    if invariant_sdk_client is None:
        raise ValueError(
            "Invariant SDK client is not initialized. Please set the INVARIANT_API_KEY environment variable."
        )

    invariant_sdk_client.create_request_and_append_messages(
        messages=session_data,
        trace_id=trace_id,
    )


async def _append_messages_to_local_file(
    trace_id: str, session_data: list[Message], record_file: LocalRecordFile
) -> None:
    """
    Append messages to the local file.
    """
    client_name = trace_client_mapping.get_client_name(trace_id)
    session_file_path = record_file.get_session_file_path(client_name)

    # Append each message as a new line
    with open(session_file_path, "a") as f:
        for message in session_data:
            f.write(json.dumps(message) + "\n")


async def push_session_to_record_file(session: Session, record_file: RecordFile, client_name: str) -> str | None:
    """
    Push a session to a record file.

    This function may be called multiple times with partially the same data. The behavior is as follows:
    - The first time we try to push for a given client, we push the data (either create it for local files or push to explorer)
    - The next time we try to push for a given client (for example from a different server) we instead append to the record file.
    We monitor which clients have been pushed to the record file by checking the trace client mapping.

    Returns the trace id.
    """
    index = session.last_pushed_index
    session_data = await _format_session_data(session, index)

    # If there are no new messages, return None
    if not session_data:
        return None

    # If we have already pushed for this client, append to the record file
    if trace_id := trace_client_mapping.get_trace_id(client_name):
        await append_messages_to_record_file(trace_id, record_file)
        return trace_id

    # Otherwise, push to the record file
    if isinstance(record_file, ExplorerRecordFile):
        trace_id = await _push_session_to_explorer(session_data, record_file, client_name)
    elif isinstance(record_file, LocalRecordFile):
        trace_id = await _push_session_to_local_file(session_data, record_file, client_name)
    else:
        raise ValueError(f"Invalid record file: {record_file}")

    # Update the last pushed index
    session.last_pushed_index += len(session_data)

    return trace_id


async def append_messages_to_record_file(trace_id: str, record_file: RecordFile) -> None:
    """
    Append messages to the record file.
    """
    client_name = trace_client_mapping.get_client_name(trace_id)
    if client_name is None:
        raise ValueError(f"Trace id {trace_id} not found in trace client mapping")

    session = session_store[client_name]
    index = session.last_pushed_index
    session_data = await _format_session_data(session, index)

    # If there are no new messages, return
    if not session_data:
        return

    # Otherwise, append to the record file
    if isinstance(record_file, ExplorerRecordFile):
        await _append_messages_to_explorer(trace_id, session_data, record_file)
    elif isinstance(record_file, LocalRecordFile):
        await _append_messages_to_local_file(trace_id, session_data, record_file)
    else:
        raise ValueError(f"Invalid record file: {record_file}")

    # Update the last pushed index
    session.last_pushed_index += len(session_data)
