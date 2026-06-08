"""
Sentinel Knowledge Base client.

Loads a SQLite database of security patterns built by
``scripts/build_knowledge_base.py``.  If the database file does not exist
locally the client attempts a one-time download from GitHub Releases.  If that
also fails the client enters a "not available" state and every caller must fall
back to hardcoded lists – this is intentional graceful degradation.

Usage::

    from orchestrator.knowledge_base import KnowledgeBase

    kb = KnowledgeBase()
    if kb.is_available():
        patterns = kb.get_patterns("java")   # ["new ObjectInputStream(", ...]
    kb.close()
"""
from __future__ import annotations

import logging
import os
import sqlite3
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_RELEASE_URL = (
    "https://github.com/anupamojha-eng/agentic-remediation-factory"
    "/releases/download/kb-latest/sentinel-kb-latest.sqlite"
)


class KnowledgeBase:
    """Local SQLite-backed knowledge base of security patterns."""

    DEFAULT_DB_PATH = os.path.join(
        os.path.dirname(__file__), "..", "training", "data", "sentinel-kb.sqlite"
    )

    def __init__(self, db_path: Optional[str] = None):
        self._db_path: str = (
            db_path
            or os.getenv("SENTINEL_KB_PATH")
            or self.DEFAULT_DB_PATH
        )
        self._conn: Optional[sqlite3.Connection] = None
        self._load()

    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------

    def _load(self) -> None:
        """Open the DB, downloading it first if the file is absent."""
        if not os.path.exists(self._db_path):
            logger.info(
                "KB not found at %s – attempting download from GitHub Releases",
                self._db_path,
            )
            if not self._download_latest():
                logger.warning(
                    "KB download failed. Pattern detection will use hardcoded fallback."
                )
                return

        try:
            self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
            # Quick schema check
            self._conn.execute("SELECT 1 FROM patterns LIMIT 1")
            logger.debug("KB loaded from %s", self._db_path)
        except Exception as exc:  # noqa: BLE001
            logger.warning("KB load error (%s): %s – using fallback.", self._db_path, exc)
            if self._conn:
                try:
                    self._conn.close()
                except Exception:  # noqa: BLE001
                    pass
            self._conn = None

    def _download_latest(self) -> bool:
        """
        Download the latest KB from GitHub Releases.

        Returns True on success, False on any failure.
        """
        try:
            import requests as _req  # lazy import – only when needed
        except ImportError:
            logger.warning("requests not installed – cannot download KB")
            return False

        try:
            logger.info("Downloading KB from %s", _RELEASE_URL)
            resp = _req.get(_RELEASE_URL, timeout=60, stream=True)
            resp.raise_for_status()

            os.makedirs(os.path.dirname(os.path.abspath(self._db_path)), exist_ok=True)
            with open(self._db_path, "wb") as fh:
                for chunk in resp.iter_content(chunk_size=1 << 16):
                    fh.write(chunk)
            logger.info("KB downloaded to %s", self._db_path)
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("KB download failed: %s", exc)
            # Remove partial file if present
            try:
                if os.path.exists(self._db_path):
                    os.remove(self._db_path)
            except OSError:
                pass
            return False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """Return True if the DB is loaded and queryable."""
        return self._conn is not None

    def get_patterns(self, language: str) -> list[str]:
        """
        Return grep-able pattern strings for the given language, ordered by
        severity (ERROR first).

        Returns ``[]`` if the DB is not available.
        """
        if self._conn is None:
            return []
        try:
            cursor = self._conn.execute(
                "SELECT grep_string FROM patterns WHERE language = ? ORDER BY severity DESC",
                (language,),
            )
            return [row[0] for row in cursor.fetchall()]
        except Exception as exc:  # noqa: BLE001
            logger.warning("KB query error: %s", exc)
            return []

    def close(self) -> None:
        """Close the underlying DB connection."""
        if self._conn:
            try:
                self._conn.close()
            except Exception:  # noqa: BLE001
                pass
            self._conn = None
