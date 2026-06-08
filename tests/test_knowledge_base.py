"""
Unit tests for orchestrator/knowledge_base.py and scripts/build_knowledge_base.py.

All tests are pure unit tests:
  - No real HTTP requests (patched out with unittest.mock)
  - No persistent filesystem side-effects (tempfile / tmp_path fixtures only)
"""
from __future__ import annotations

import importlib
import importlib.util
import os
import sqlite3
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_db(tmp_path: Path, rows: list[dict] | None = None) -> str:
    """Create a minimal sentinel-kb.sqlite at tmp_path and return its path."""
    db_path = str(tmp_path / "sentinel-kb.sqlite")
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS patterns (
            id TEXT PRIMARY KEY,
            language TEXT NOT NULL,
            grep_string TEXT NOT NULL,
            severity TEXT DEFAULT 'WARNING',
            cwe TEXT DEFAULT '',
            description TEXT DEFAULT '',
            source TEXT DEFAULT 'semgrep'
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    if rows:
        for row in rows:
            conn.execute(
                "INSERT INTO patterns (id, language, grep_string, severity, cwe, description, source) "
                "VALUES (:id, :language, :grep_string, :severity, :cwe, :description, :source)",
                row,
            )
    conn.commit()
    conn.close()
    return db_path


# ---------------------------------------------------------------------------
# KnowledgeBase tests
# ---------------------------------------------------------------------------

class TestKnowledgeBaseUnavailable:
    def test_returns_empty_list_when_db_not_available(self, tmp_path: Path):
        """KB with no DB file and a failed download returns [] for get_patterns()."""
        missing_path = str(tmp_path / "nonexistent.sqlite")

        with patch(
            "orchestrator.knowledge_base.KnowledgeBase._download_latest",
            return_value=False,
        ):
            from orchestrator.knowledge_base import KnowledgeBase
            kb = KnowledgeBase(db_path=missing_path)

        assert kb.is_available() is False
        assert kb.get_patterns("java") == []
        assert kb.get_patterns("python") == []

    def test_is_available_false_when_no_db(self, tmp_path: Path):
        missing = str(tmp_path / "no.sqlite")
        with patch("orchestrator.knowledge_base.KnowledgeBase._download_latest", return_value=False):
            from orchestrator.knowledge_base import KnowledgeBase
            kb = KnowledgeBase(db_path=missing)
        assert kb.is_available() is False


class TestKnowledgeBaseWithDB:
    def test_get_patterns_queries_by_language(self, tmp_path: Path):
        """get_patterns() returns only patterns for the requested language."""
        rows = [
            {"id": "r1", "language": "java", "grep_string": "Runtime.getRuntime().exec(",
             "severity": "ERROR", "cwe": "CWE-78", "description": "cmd inj", "source": "builtin"},
            {"id": "r2", "language": "python", "grep_string": "yaml.load(",
             "severity": "ERROR", "cwe": "CWE-502", "description": "yaml", "source": "builtin"},
            {"id": "r3", "language": "java", "grep_string": "new ProcessBuilder(",
             "severity": "WARNING", "cwe": "CWE-78", "description": "pb", "source": "semgrep"},
        ]
        db_path = _make_db(tmp_path, rows)

        from orchestrator.knowledge_base import KnowledgeBase
        kb = KnowledgeBase(db_path=db_path)

        java_patterns = kb.get_patterns("java")
        python_patterns = kb.get_patterns("python")

        assert "Runtime.getRuntime().exec(" in java_patterns
        assert "new ProcessBuilder(" in java_patterns
        assert "yaml.load(" not in java_patterns

        assert "yaml.load(" in python_patterns
        assert "Runtime.getRuntime().exec(" not in python_patterns

        kb.close()

    def test_get_patterns_severity_ordering(self, tmp_path: Path):
        """ERROR patterns come before WARNING patterns."""
        rows = [
            {"id": "w1", "language": "java", "grep_string": "warning_pattern(",
             "severity": "WARNING", "cwe": "", "description": "", "source": "semgrep"},
            {"id": "e1", "language": "java", "grep_string": "error_pattern(",
             "severity": "ERROR", "cwe": "", "description": "", "source": "builtin"},
        ]
        db_path = _make_db(tmp_path, rows)
        from orchestrator.knowledge_base import KnowledgeBase
        kb = KnowledgeBase(db_path=db_path)
        patterns = kb.get_patterns("java")
        # ERROR should come first (ORDER BY severity DESC → E before W)
        assert patterns.index("error_pattern(") < patterns.index("warning_pattern(")
        kb.close()

    def test_is_available_true_when_db_exists(self, tmp_path: Path):
        db_path = _make_db(tmp_path)
        from orchestrator.knowledge_base import KnowledgeBase
        kb = KnowledgeBase(db_path=db_path)
        assert kb.is_available() is True
        kb.close()


class TestKnowledgeBaseDownload:
    def test_download_attempted_when_db_missing(self, tmp_path: Path):
        """_download_latest() is called when the DB file doesn't exist."""
        missing = str(tmp_path / "missing.sqlite")

        with patch(
            "orchestrator.knowledge_base.KnowledgeBase._download_latest",
            return_value=False,
        ) as mock_dl:
            from orchestrator.knowledge_base import KnowledgeBase
            KnowledgeBase(db_path=missing)

        mock_dl.assert_called_once()

    def test_download_not_attempted_when_db_exists(self, tmp_path: Path):
        """_download_latest() is NOT called when the DB file already exists."""
        db_path = _make_db(tmp_path)

        with patch(
            "orchestrator.knowledge_base.KnowledgeBase._download_latest",
            return_value=False,
        ) as mock_dl:
            from orchestrator.knowledge_base import KnowledgeBase
            kb = KnowledgeBase(db_path=db_path)
            kb.close()

        mock_dl.assert_not_called()

    def test_graceful_degradation_on_download_failure(self, tmp_path: Path):
        """If download fails, is_available() returns False, no exception raised."""
        missing = str(tmp_path / "missing.sqlite")

        with patch(
            "orchestrator.knowledge_base.KnowledgeBase._download_latest",
            return_value=False,
        ):
            from orchestrator.knowledge_base import KnowledgeBase
            kb = KnowledgeBase(db_path=missing)

        # No exception; is_available is False
        assert kb.is_available() is False
        assert kb.get_patterns("java") == []
        kb.close()

    def test_graceful_degradation_on_requests_missing(self, tmp_path: Path):
        """If requests is not importable, _download_latest returns False gracefully."""
        missing = str(tmp_path / "missing2.sqlite")

        # Simulate requests being unavailable inside _download_latest
        with patch("builtins.__import__", side_effect=_make_import_blocker("requests")):
            try:
                from orchestrator import knowledge_base as _kb_mod
                importlib.reload(_kb_mod)
                kb = _kb_mod.KnowledgeBase(db_path=missing)
                assert kb.is_available() is False
            except ImportError:
                pass  # also acceptable – module itself imports requests lazily


def _make_import_blocker(blocked_name: str):
    """Return a side_effect for __import__ that blocks a specific module."""
    import builtins
    original = builtins.__import__

    def _blocker(name, *args, **kwargs):
        if name == blocked_name:
            raise ImportError(f"Mocked ImportError for {blocked_name}")
        return original(name, *args, **kwargs)

    return _blocker


# ---------------------------------------------------------------------------
# build_knowledge_base.py script tests
# ---------------------------------------------------------------------------

class TestBuildScript:
    def _load_script(self):
        """Import the build script as a module."""
        script_path = os.path.join(
            os.path.dirname(__file__), "..", "scripts", "build_knowledge_base.py"
        )
        spec = importlib.util.spec_from_file_location("build_knowledge_base", script_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_build_script_writes_builtin_patterns(self, tmp_path: Path):
        """
        build() writes builtin patterns even when Semgrep download is mocked to fail.
        """
        mod = self._load_script()

        with patch.object(mod, "_download_semgrep_rules", return_value=False):
            db_path = mod.build(output_dir=str(tmp_path))

        assert os.path.exists(db_path)
        conn = sqlite3.connect(db_path)
        rows = conn.execute(
            "SELECT grep_string, source FROM patterns WHERE source='builtin'"
        ).fetchall()
        conn.close()

        grep_strings = {r[0] for r in rows}
        # Java builtins
        assert "Runtime.getRuntime().exec(" in grep_strings
        assert "new ObjectInputStream(" in grep_strings
        # Python builtins
        assert "yaml.load(" in grep_strings
        assert "pickle.loads(" in grep_strings

    def test_build_script_metadata_table(self, tmp_path: Path):
        """build() writes a 'built_at' entry to the metadata table."""
        mod = self._load_script()

        with patch.object(mod, "_download_semgrep_rules", return_value=False):
            db_path = mod.build(output_dir=str(tmp_path))

        conn = sqlite3.connect(db_path)
        row = conn.execute(
            "SELECT value FROM metadata WHERE key='built_at'"
        ).fetchone()
        conn.close()

        assert row is not None
        assert row[0]  # non-empty date string

    def test_build_script_semgrep_failure_still_produces_db(self, tmp_path: Path):
        """Even if Semgrep network calls fail, the DB is written with builtins."""
        mod = self._load_script()

        with patch.object(mod, "_requests", None):
            db_path = mod.build(output_dir=str(tmp_path))

        assert os.path.exists(db_path)
        conn = sqlite3.connect(db_path)
        count = conn.execute("SELECT COUNT(*) FROM patterns").fetchone()[0]
        conn.close()
        # at least the builtins
        assert count >= len(mod._BUILTIN_JAVA) + len(mod._BUILTIN_PYTHON)

    def test_extract_grep_strings_finds_function_calls(self):
        """_extract_grep_strings() extracts patterns containing '('."""
        mod = self._load_script()
        rule = {
            "id": "test-rule",
            "pattern": "Runtime.getRuntime().exec(args)",
            "message": "cmd injection",
        }
        results = mod._extract_grep_strings(rule)
        assert any("Runtime.getRuntime().exec(" in r for r in results)

    def test_extract_grep_strings_pattern_either(self):
        """_extract_grep_strings() recurses into pattern-either."""
        mod = self._load_script()
        rule = {
            "id": "test-rule",
            "pattern-either": [
                {"pattern": "yaml.load(data)"},
                {"pattern": "pickle.loads(data)"},
            ],
        }
        results = mod._extract_grep_strings(rule)
        assert "yaml.load(" in results
        assert "pickle.loads(" in results

    def test_language_from_path(self):
        mod = self._load_script()
        assert mod._language_from_path("java/lang/security/foo.yml") == "java"
        assert mod._language_from_path("python/lang/security/bar.yml") == "python"
        assert mod._language_from_path("go/some/rule.yml") == "unknown"


# ---------------------------------------------------------------------------
# llm_client.py integration tests
# ---------------------------------------------------------------------------

class TestLLMClientKBIntegration:
    """Tests for SecurityAgentClient KB integration (KB and LLM both mocked)."""

    def _make_client_with_kb(self, kb_mock):
        """Create a SecurityAgentClient with a mocked LLM provider and injected KB."""
        # Patch _make_provider to avoid needing real API keys
        mock_llm = MagicMock()
        mock_llm.model_id = "test-model"

        with patch("orchestrator.llm_client._make_provider", return_value=mock_llm), \
             patch("orchestrator.knowledge_base.KnowledgeBase", return_value=kb_mock):
            from orchestrator.llm_client import SecurityAgentClient
            client = SecurityAgentClient()
        # Inject directly to be safe
        client._kb = kb_mock
        client.llm = mock_llm
        return client

    def test_llm_client_uses_kb_when_available(self, tmp_path: Path):
        """When KB is available, get_vulnerable_patterns() uses KB patterns."""
        kb_mock = MagicMock()
        kb_mock.is_available.return_value = True
        kb_mock.get_patterns.return_value = ["custom_pattern(", "another_pattern("]

        client = self._make_client_with_kb(kb_mock)

        # No unknown GHSAs → no LLM call needed
        patterns = client.get_vulnerable_patterns([], build_system="java")

        kb_mock.get_patterns.assert_called_once_with("java")
        assert "custom_pattern(" in patterns
        assert "another_pattern(" in patterns

    def test_llm_client_falls_back_to_hardcoded_when_kb_unavailable(self, tmp_path: Path):
        """When KB is unavailable, hardcoded lists are used instead."""
        kb_mock = MagicMock()
        kb_mock.is_available.return_value = False

        client = self._make_client_with_kb(kb_mock)

        patterns = client.get_vulnerable_patterns([], build_system="python")

        # KB.get_patterns() should NOT be called
        kb_mock.get_patterns.assert_not_called()
        # Must contain the hardcoded Python patterns
        assert "yaml.load(" in patterns
        assert "pickle.loads(" in patterns

    def test_llm_client_falls_back_java_hardcoded(self, tmp_path: Path):
        """Java hardcoded fallback when KB is unavailable."""
        kb_mock = MagicMock()
        kb_mock.is_available.return_value = False

        client = self._make_client_with_kb(kb_mock)

        patterns = client.get_vulnerable_patterns([], build_system="maven")

        kb_mock.get_patterns.assert_not_called()
        assert "Runtime.getRuntime().exec(" in patterns
        assert "new ObjectInputStream(" in patterns

    def test_llm_client_known_patterns_still_added(self):
        """GHSA IDs in _KNOWN_PATTERNS are always appended regardless of KB."""
        kb_mock = MagicMock()
        kb_mock.is_available.return_value = True
        kb_mock.get_patterns.return_value = []

        client = self._make_client_with_kb(kb_mock)

        patterns = client.get_vulnerable_patterns(
            ["GHSA-jjjh-jjxp-wpff"], build_system="maven"
        )
        assert "enableDefaultTyping" in patterns

    def test_llm_client_kb_python_language_key(self):
        """KB is queried with 'python' for python build systems."""
        kb_mock = MagicMock()
        kb_mock.is_available.return_value = True
        kb_mock.get_patterns.return_value = []

        client = self._make_client_with_kb(kb_mock)
        client.get_vulnerable_patterns([], build_system="python")

        kb_mock.get_patterns.assert_called_once_with("python")

    def test_llm_client_kb_java_language_key_gradle(self):
        """KB is queried with 'java' for gradle build systems."""
        kb_mock = MagicMock()
        kb_mock.is_available.return_value = True
        kb_mock.get_patterns.return_value = []

        client = self._make_client_with_kb(kb_mock)
        client.get_vulnerable_patterns([], build_system="gradle")

        kb_mock.get_patterns.assert_called_once_with("java")
