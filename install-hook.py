#!/usr/bin/env python3
"""
Install Cursor hooks for mcp-scan gateway.

This script generates a hooks.json file and places it in ~/.cursor/hooks.json
with the correct paths to the uv binary, project root, and hook-gateway.py script.
"""

import json
import os
import shutil
import sys
from pathlib import Path


def find_uv_binary() -> str:
    """Find the uv binary in the system PATH."""
    uv_path = shutil.which("uv")
    if not uv_path:
        print("Error: 'uv' binary not found in PATH.", file=sys.stderr)
        print("Please install uv first: https://docs.astral.sh/uv/", file=sys.stderr)
        sys.exit(1)
    return uv_path


def get_project_root() -> str:
    """Get the absolute path to the project root (current directory)."""
    return str(Path(__file__).parent.resolve())


def get_hook_gateway_path(project_root: str) -> str:
    """Get the absolute path to hook-gateway.py."""
    hook_path = Path(project_root) / "hook-gateway.py"
    if not hook_path.exists():
        print(f"Error: hook-gateway.py not found at {hook_path}", file=sys.stderr)
        sys.exit(1)
    return str(hook_path)


def generate_hooks_config(uv_binary: str, project_root: str, hook_gateway_path: str) -> dict:
    """Generate the hooks configuration dictionary."""
    command = f"{uv_binary} run --project {project_root} python {hook_gateway_path}"
    
    return {
        "version": 1,
        "hooks": {
            "beforeShellExecution": [
                {"command": command}
            ],
            "beforeMCPExecution": [
                {"command": command}
            ],
            "beforeReadFile": [
                {"command": command}
            ],
            "afterFileEdit": [
                {"command": command}
            ],
            "beforeSubmitPrompt": [
                {"command": command}
            ],
            "stop": [
                {"command": command}
            ]
        }
    }


def install_hooks(config: dict, hooks_file_path: Path) -> None:
    """Write the hooks configuration to the specified file."""
    # Create the directory if it doesn't exist
    hooks_file_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Backup existing hooks file if it exists
    if hooks_file_path.exists():
        backup_path = hooks_file_path.with_suffix('.json.backup')
        print(f"Backing up existing hooks file to {backup_path}")
        shutil.copy2(hooks_file_path, backup_path)
    
    # Write the new hooks configuration
    with open(hooks_file_path, 'w') as f:
        json.dump(config, f, indent=2)
    
    print(f"✓ Hooks configuration installed to {hooks_file_path}")


def main():
    """Main installation function."""
    print("Installing Cursor hooks for mcp-scan gateway...")
    print()
    
    # Find uv binary
    uv_binary = find_uv_binary()
    print(f"✓ Found uv binary: {uv_binary}")
    
    # Get project root
    project_root = get_project_root()
    print(f"✓ Project root: {project_root}")
    
    # Get hook-gateway.py path
    hook_gateway_path = get_hook_gateway_path(project_root)
    print(f"✓ Hook gateway script: {hook_gateway_path}")
    
    # Generate hooks configuration
    config = generate_hooks_config(uv_binary, project_root, hook_gateway_path)
    
    # Install hooks
    hooks_file_path = Path.home() / ".cursor" / "hooks.json"
    install_hooks(config, hooks_file_path)
    
    print()
    print("Installation complete!")
    print()
    print("The following hooks have been configured:")
    for hook_name in config["hooks"].keys():
        print(f"  - {hook_name}")
    print()
    print("Note: You may need to restart Cursor for the hooks to take effect.")


if __name__ == "__main__":
    main()

