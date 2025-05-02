import asyncio
import json
import os
from datetime import datetime

import rich
import yaml  # type: ignore
from pydantic import ValidationError

from mcp_scan_server.models import GuardrailConfigFile

from .models import Entity, ScannedEntities, ScannedEntity, entity_type_to_str, hash_entity
from .utils import upload_whitelist_entry


class StorageFile:
    def __init__(self, path: str):
        self.path = os.path.expanduser(path)

        # if path is a file
        self.scanned_entities: ScannedEntities = ScannedEntities({})
        self.whitelist: dict[str, str] = {}
        self.guardrails_config: GuardrailConfigFile = GuardrailConfigFile()

        if os.path.isfile(self.path):
            rich.print(f"[bold]Legacy storage file detected at {self.path}, converting to new format[/bold]")
            # legacy format
            with open(self.path, "r") as f:
                legacy_data = json.load(f)
            if "__whitelist" in legacy_data:
                self.whitelist = legacy_data["__whitelist"]
                del legacy_data["__whitelist"]
            try:
                self.scanned_entities = ScannedEntities.model_validate(legacy_data)
            except ValidationError as e:
                rich.print(f"[bold red]Could not load legacy storage file {self.path}: {e}[/bold red]")
            os.remove(path)

        if os.path.exists(self.path) and os.path.isdir(self.path):
            scanned_entities_path = os.path.join(self.path, "scanned_entities.json")
            if os.path.exists(scanned_entities_path):
                with open(scanned_entities_path, "r") as f:
                    try:
                        self.scanned_entities = ScannedEntities.model_validate_json(f.read())
                    except ValidationError as e:
                        rich.print(
                            f"[bold red]Could not load scanned entities file {scanned_entities_path}: {e}[/bold red]"
                        )
            if os.path.exists(os.path.join(self.path, "whitelist.json")):
                with open(os.path.join(self.path, "whitelist.json"), "r") as f:
                    self.whitelist = json.load(f)

            guardrails_config_path = os.path.join(self.path, "guardrails_config.yml")
            if os.path.exists(guardrails_config_path):
                with open(guardrails_config_path, "r") as f:
                    try:
                        guardrails_config_data = yaml.safe_load(f.read()) or {}
                        self.guardrails_config = GuardrailConfigFile.model_validate(guardrails_config_data)
                    except yaml.YAMLError as e:
                        rich.print(
                            f"[bold red]Could not parse guardrails config file "
                            f"{guardrails_config_path}: {e}[/bold red]"
                        )
                    except ValidationError as e:
                        rich.print(
                            f"[bold red]Could not validate guardrails config file "
                            f"{guardrails_config_path}: {e}[/bold red]"
                        )

    def reset_whitelist(self) -> None:
        self.whitelist = {}
        self.save()

    def check_and_update(self, server_name: str, entity: Entity, verified: bool | None) -> tuple[bool, list[str]]:
        entity_type = entity_type_to_str(entity)
        key = f"{server_name}.{entity_type}.{entity.name}"
        hash = hash_entity(entity)
        new_data = ScannedEntity(
            hash=hash,
            type=entity_type,
            verified=verified,
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
                messages.append(
                    f"[bold]Previous description[/bold] ({prev_data.timestamp.strftime('%d/%m/%Y, %H:%M:%S')})"
                )
                messages.append(prev_data.description)
        self.scanned_entities.root[key] = new_data
        return changed, messages

    def print_whitelist(self) -> None:
        whitelist_keys = sorted(self.whitelist.keys())
        for key in whitelist_keys:
            if "." in key:
                entity_type, name = key.split(".", 1)
            else:
                entity_type, name = "tool", key
            rich.print(entity_type, name, self.whitelist[key])
        rich.print(f"[bold]{len(whitelist_keys)} entries in whitelist[/bold]")

    def add_to_whitelist(self, entity_type: str, name: str, hash: str, base_url: str | None = None) -> None:
        key = f"{entity_type}.{name}"
        self.whitelist[key] = hash
        self.save()
        if base_url is not None:
            try:
                asyncio.run(upload_whitelist_entry(name, hash, base_url))
            except Exception:
                pass  # no logging for now, can fail silently

    def is_whitelisted(self, entity: Entity) -> bool:
        hash = hash_entity(entity)
        return hash in self.whitelist.values()

    def create_guardrails_config(self) -> str:
        """
        If the guardrails config file does not exist, create it with default values.

        Returns the path to the guardrails config file.
        """
        guardrails_config_path = os.path.join(self.path, "guardrails_config.yml")
        if not os.path.exists(guardrails_config_path):
            with open(guardrails_config_path, "w") as f:
                if self.guardrails_config is not None:
                    f.write(self.guardrails_config.model_dump_yaml())
        return guardrails_config_path

    def save(self) -> None:
        os.makedirs(self.path, exist_ok=True)
        with open(os.path.join(self.path, "scanned_entities.json"), "w") as f:
            f.write(self.scanned_entities.model_dump_json())
        with open(os.path.join(self.path, "whitelist.json"), "w") as f:
            json.dump(self.whitelist, f)
        with open(os.path.join(self.path, "guardrails_config.yml"), "w") as f:
            f.write(self.guardrails_config.model_dump_yaml())
