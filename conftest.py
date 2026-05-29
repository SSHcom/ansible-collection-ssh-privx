"""Root conftest.py — makes the collection importable as ansible_collections.sshcom.privx."""

import sys
from pathlib import Path

# Create a virtual namespace package structure so that
# `ansible_collections.sshcom.privx` resolves to this repository root.
_REPO_ROOT = Path(__file__).resolve().parent

# We need: <some_dir>/ansible_collections/sshcom/privx -> _REPO_ROOT
# Create a temporary directory structure using symlinks
_COLLECTIONS_DIR = _REPO_ROOT / ".collections"
_NS_DIR = _COLLECTIONS_DIR / "ansible_collections" / "sshcom" / "privx"

if not _NS_DIR.exists():
    _NS_DIR.parent.mkdir(parents=True, exist_ok=True)
    _NS_DIR.symlink_to(_REPO_ROOT)

# Add the .collections dir to sys.path so imports resolve
_collections_str = str(_COLLECTIONS_DIR)
if _collections_str not in sys.path:
    sys.path.insert(0, _collections_str)
