"""Shared fixtures for p11test PKCS#11 test cases.

Note: Test skipping for missing module, version, and destructive markers
is handled in plugin.py's pytest_collection_modifyitems hook.
"""

from __future__ import annotations
