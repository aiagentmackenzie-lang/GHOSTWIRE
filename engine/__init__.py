"""GHOSTWIRE — Network Forensics Engine.

The wire remembers everything.

Version note: this value is the single source of truth for the version the
engine reports. It must match ``pyproject.toml``; ``tests/test_version.py``
fails if they drift (the audit found 0.2.1 packaged vs 0.2.0 reported).
"""

__version__ = "0.3.0"
__author__ = "Raphael Main + Agent Mackenzie"
