"""Honeypath — a defensive credential-canary monitor.

Honeypath plants obviously-fake credential files at locations that
credential-stealing malware and malicious packages routinely scrape, watches
them for access, records events in SQLite, and alerts via Pushover.

This is a *detection* tool, not a prevention tool.  Nothing here blocks,
hides, tampers, or escalates.
"""

__version__ = "0.1.0"

VERSION = __version__

# Marker embedded in generated files so Honeypath can recognise its own work.
MANAGED_MARKER = "HONEYPATH"

__all__ = ["__version__", "VERSION", "MANAGED_MARKER"]
