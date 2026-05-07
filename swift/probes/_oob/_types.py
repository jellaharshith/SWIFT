"""Shared types for OOB callback infrastructure — re-exports from server."""
# CallbackEvent lives in server.py to avoid circular imports.
# This module exists for backward-compat imports.
from .server import CallbackEvent

__all__ = ["CallbackEvent"]
