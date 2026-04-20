"""Unit tests for web.storage engine factory — no real DB connection made."""
from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

import web.storage as storage_mod


def test_create_engine_uses_database_url_when_set():
    """When DATABASE_URL is set, engine should use the PostgreSQL URL."""
    pg_url = "postgresql://user:pass@localhost/testdb"
    mock_engine = MagicMock()
    mock_engine.url = pg_url  # enough for the assertion

    with patch.object(storage_mod, "_DATABASE_URL", pg_url), \
         patch("web.storage.create_engine", return_value=mock_engine) as mock_ce:
        engine, SessionLocal = storage_mod.create_engine_and_session()

    # create_engine must have been called with the PostgreSQL URL (no SQLite args)
    mock_ce.assert_called_once_with(pg_url)
    assert engine is mock_engine


def test_create_engine_falls_back_to_sqlite_without_database_url():
    """Without DATABASE_URL, engine should use SQLite."""
    with patch.object(storage_mod, "_DATABASE_URL", None):
        engine, SessionLocal = storage_mod.create_engine_and_session()
    assert "sqlite" in str(engine.url)
