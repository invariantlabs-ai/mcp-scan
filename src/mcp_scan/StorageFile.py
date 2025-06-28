import asyncio
import contextlib
import json
import logging
import os
from datetime import datetime

import rich
import yaml  # type: ignore
from pydantic import ValidationError

from mcp_scan_server.models import DEFAULT_GUARDRAIL_CONFIG, GuardrailConfigFile

from .models import Entity, ScannedEntities, ScannedEntity, entity_type_to_str, hash_entity
from .utils import upload_whitelist_entry

# Set up logger for this module
logger = logging.getLogger(__name__)


class StorageFile:
    def __init__(self, path: str):
        logger.debug("Initializing StorageFile with path: %s", path)
        self.path = os.path.expanduser(path)

        logger.debug("Expanded path: %s", self.path)
        # if path is a file
        self.scanned_entities: ScannedEntities = ScannedEntities({})
        self.whitelist: dict[str, str] = {}
        self.guardrails_config: GuardrailConfigFile = GuardrailConfigFile()

        if os.path.isfile(self.path):
            rich.print(f"[bold]Legacy storage file detected at {self.path}, converting to new format[/bold]")
            # legacy format
            with open(self.path) as f:
                legacy_data = json.load(f)
            if "__whitelist" in legacy_data:
                self.whitelist = legacy_data["__whitelist"]
                del legacy_data["__whitelist"]

            try:
                logger.debug("Loading legacy format file")
                with open(path) as f:
                    legacy_data = json.load(f)
                if "__whitelist" in legacy_data:
                    logger.debug("Found whitelist in legacy data with %d entries", len(legacy_data["__whitelist"]))
                    self.whitelist = legacy_data["__whitelist"]
                    del legacy_data["__whitelist"]
                try:
                    self.scanned_entities = ScannedEntities.model_validate(legacy_data)
                    logger.info("Successfully loaded legacy scanned entities data")
                except ValidationError as e:
                    error_msg = f"Could not load legacy storage file {self.path}: {e}"
                    logger.error(error_msg)
                    rich.print(f"[bold red]{error_msg}[/bold red]")
                os.remove(path)
                logger.info("Removed legacy storage file after conversion")
            except Exception:
                logger.exception("Error processing legacy storage file: %s", path)

        if os.path.exists(path) and os.path.isdir(path):
            logger.debug("Path exists and is a directory: %s", path)
            scanned_entities_path = os.path.join(path, "scanned_entities.json")

            if os.path.exists(scanned_entities_path):
                logger.debug("Loading scanned entities from: %s", scanned_entities_path)
                with open(scanned_entities_path) as f:
                    try:
                        self.scanned_entities = ScannedEntities.model_validate_json(f.read())
                        logger.info("Successfully loaded scanned entities data")
                    except ValidationError as e:
                        error_msg = f"Could not load scanned entities file {scanned_entities_path}: {e}"
                        logger.error(error_msg)
                        rich.print(f"[bold red]{error_msg}[/bold red]")
            whitelist_path = os.path.join(path, "whitelist.json")
            if os.path.exists(whitelist_path):
                logger.debug("Loading whitelist from: %s", whitelist_path)
                with open(whitelist_path) as f:
                    self.whitelist = json.load(f)
                    logger.info("Successfully loaded whitelist with %d entries", len(self.whitelist))

            guardrails_config_path = os.path.join(self.path, "guardrails_config.yml")
            if os.path.exists(guardrails_config_path):
                with open(guardrails_config_path) as f:
                    try:
                        guardrails_config_data = yaml.safe_load(f.read()) or {}
                        self.guardrails_config = GuardrailConfigFile.model_validate(guardrails_config_data)
                    except yaml.YAMLError as e:
                        rich.print(
                            f"[bold red]Could not parse guardrails config file {guardrails_config_path}: {e}[/bold red]"
                        )
                    except ValidationError as e:
                        rich.print(
                            f"[bold red]Could not validate guardrails config file "
                            f"{guardrails_config_path}: {e}[/bold red]"
                        )

    def reset_whitelist(self) -> None:
        logger.info("Resetting whitelist")
        self.whitelist = {}
        self.save()

    def check_and_update(self, server_name: str, entity: Entity) -> tuple[bool, list[str]]:
        logger.debug("Checking entity: %s in server: %s", entity.name, server_name)
        entity_type = entity_type_to_str(entity)
        key = f"{server_name}.{entity_type}.{entity.name}"
        hash = hash_entity(entity)

        new_data = ScannedEntity(
            hash=hash,
            type=entity_type,
            timestamp=datetime.now(),
            description=entity.description,
        )
        changed = False
        messages = []
        prev_data = None
        if key in self.scanned_entities.root:
            prev_data = self.scanned_entities.root[key]
            changed = prev_data.hash != new_data.hash
            if changed:
                logger.info("Entity %s has changed since last scan", entity.name)
                logger.debug("Previous hash: %s, new hash: %s", prev_data.hash, new_data.hash)
                messages.append(
                    f"[bold]Previous description[/bold] ({prev_data.timestamp.strftime('%d/%m/%Y, %H:%M:%S')})"
                )
                messages.append(prev_data.description)
        else:
            logger.debug("Entity %s is new (not previously scanned)", entity.name)

        self.scanned_entities.root[key] = new_data
        return changed, messages

    def print_whitelist(self) -> None:
        logger.info("Printing whitelist with %d entries", len(self.whitelist))
        whitelist_keys = sorted(self.whitelist.keys())
        for key in whitelist_keys:
            if "." in key:
                entity_type, name = key.split(".", 1)
            else:
                entity_type, name = "tool", key
            logger.debug("Whitelist entry: %s - %s - %s", entity_type, name, self.whitelist[key])
            rich.print(entity_type, name, self.whitelist[key])
        rich.print(f"[bold]{len(whitelist_keys)} entries in whitelist[/bold]")

    def add_to_whitelist(self, entity_type: str, name: str, hash: str, base_url: str | None = None) -> None:
        key = f"{entity_type}.{name}"
        logger.info("Adding to whitelist: %s with hash: %s", key, hash)
        self.whitelist[key] = hash
        self.save()
        if base_url is not None:
            logger.debug("Uploading whitelist entry to base URL: %s", base_url)
            with contextlib.suppress(Exception):
                try:
                    asyncio.run(upload_whitelist_entry(name, hash, base_url))
                    logger.info("Successfully uploaded whitelist entry to remote server")
                except Exception as e:
                    logger.warning("Failed to upload whitelist entry: %s", e)

    def is_whitelisted(self, entity: Entity) -> bool:
        hash = hash_entity(entity)
        result = hash in self.whitelist.values()
        logger.debug("Checking if entity %s is whitelisted: %s", entity.name, result)
        return result

    def create_guardrails_config(self) -> str:
        """
        If the guardrails config file does not exist, create it with default values.

        Returns the path to the guardrails config file.
        """
        guardrails_config_path = os.path.join(self.path, "guardrails_config.yml")
        if not os.path.exists(guardrails_config_path):
            # make sure the directory exists (otherwise the write below will fail)
            if not os.path.exists(self.path):
                os.makedirs(self.path, exist_ok=True)
            logger.debug("Creating guardrails config file at: %s", guardrails_config_path)

            with open(guardrails_config_path, "w") as f:
                if self.guardrails_config is not None:
                    f.write(DEFAULT_GUARDRAIL_CONFIG)
        return guardrails_config_path

    def save(self) -> None:
        logger.info("Saving storage data to %s", self.path)
        try:
            os.makedirs(self.path, exist_ok=True)
            scanned_entities_path = os.path.join(self.path, "scanned_entities.json")
            logger.debug("Saving scanned entities to: %s", scanned_entities_path)
            with open(scanned_entities_path, "w") as f:
                f.write(self.scanned_entities.model_dump_json())

            whitelist_path = os.path.join(self.path, "whitelist.json")
            logger.debug("Saving whitelist to: %s", whitelist_path)
            with open(whitelist_path, "w") as f:
                json.dump(self.whitelist, f)
            logger.info("Successfully saved storage files")
        except Exception as e:
            logger.exception("Error saving storage files: %s", e)
