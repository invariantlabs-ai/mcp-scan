import logging
import os
import pathlib
import uuid

from pydantic import ValidationError

from mcp_scan.models import ScanUserID

logger = logging.getLogger(__name__)


DEFAULT_IDENTITY_PATH = pathlib.Path("~/.mcp-scan/identity.json").expanduser()


class IdentityManager:
    """
    Manages the scanner's identity by loading from a file or creating a new one.

    The identity is loaded lazily upon first access of the `identity` property.
    If the identity file is missing or corrupted, a new one is automatically created.
    """

    def __init__(self, path: os.PathLike = DEFAULT_IDENTITY_PATH):
        self.path = pathlib.Path(path)
        self._identity: ScanUserID | None = None
        self._load_or_create()

    def _load_or_create(self):
        """Loads identity from path or creates a new one, populating self._identity."""
        if self.path.exists():
            try:
                self._identity = ScanUserID.model_validate_json(self.path.read_text())
                return
            except (ValidationError, ValueError):
                # File is malformed or not valid JSON. A new one will be created.
                logger.warning("Identity file is malformed or not valid JSON. A new one will be created.")
                pass

        # Create and save a new identity if the file doesn't exist or was invalid
        new_identity = ScanUserID(uuid=str(uuid.uuid4()))
        self._save(new_identity)
        self._identity = new_identity

    def _save(self, identity: ScanUserID):
        """Saves the provided identity object to the JSON file."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(identity.model_dump_json(indent=2))

    def get_identity(self, regenerate: bool = False) -> ScanUserID | None:
        """
        Get the scanner's identity. If regenerate is True, a new identity is created and saved.
        """
        if regenerate or self._identity is None:
            self._identity = ScanUserID(uuid=str(uuid.uuid4()))
            self._save(self._identity)
        return self._identity
