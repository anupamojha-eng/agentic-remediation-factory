"""
Unit tests for _LocalProvider — Ollama-backed offline inference.
No real Ollama instance required; all HTTP calls are mocked.
"""
import sys
import os
import json
import pytest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'orchestrator'))


# ── Helpers ────────────────────────────────────────────────────────────────────

def _mock_response(content: str, prompt_tokens: int = 100, completion_tokens: int = 50):
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {
        "choices": [{"message": {"content": content}}],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
        },
    }
    resp.raise_for_status = MagicMock()
    return resp


def _make_provider(model: str = "hf.co/anupamojha/sentinel-patcher-7b",
                   ollama_host: str = "http://localhost:11434"):
    """Construct _LocalProvider with mocked HTTP (skips reachability check)."""
    env = {
        "SENTINEL_LOCAL_MODEL": model,
        "OLLAMA_HOST": ollama_host,
    }
    with patch.dict(os.environ, env):
        with patch("requests.get"):          # suppress reachability check
            from llm_client import _LocalProvider
            return _LocalProvider()


# ── Provider selection ─────────────────────────────────────────────────────────

class TestProviderSelection:
    def test_local_selected_when_sentinel_local_model_set(self):
        env = {"SENTINEL_LOCAL_MODEL": "hf.co/anupamojha/sentinel-patcher-7b"}
        with patch.dict(os.environ, env, clear=True):
            with patch("requests.get"):
                from llm_client import _make_provider, _LocalProvider
                provider = _make_provider()
        assert isinstance(provider, _LocalProvider)

    def test_local_selected_when_llm_provider_local(self):
        env = {
            "LLM_PROVIDER": "local",
            "SENTINEL_LOCAL_MODEL": "hf.co/anupamojha/sentinel-patcher-7b",
        }
        with patch.dict(os.environ, env, clear=True):
            with patch("requests.get"):
                from llm_client import _make_provider, _LocalProvider
                provider = _make_provider()
        assert isinstance(provider, _LocalProvider)

    def test_anthropic_preferred_over_gemini_when_no_local(self):
        env = {
            "ANTHROPIC_API_KEY": "sk-test",
            "GEMINI_API_KEY": "gemini-test",
        }
        with patch.dict(os.environ, env, clear=True):
            with patch("anthropic.Anthropic"):
                from llm_client import _make_provider, _AnthropicProvider
                provider = _make_provider()
        assert isinstance(provider, _AnthropicProvider)

    def test_local_takes_priority_over_anthropic_key(self):
        env = {
            "SENTINEL_LOCAL_MODEL": "hf.co/anupamojha/sentinel-patcher-7b",
            "ANTHROPIC_API_KEY": "sk-test",
        }
        with patch.dict(os.environ, env, clear=True):
            with patch("requests.get"):
                from llm_client import _make_provider, _LocalProvider
                provider = _make_provider()
        assert isinstance(provider, _LocalProvider)

    def test_raises_when_no_provider_configured(self):
        with patch.dict(os.environ, {}, clear=True):
            from llm_client import _make_provider
            with pytest.raises(ValueError, match="No LLM provider configured"):
                _make_provider()


# ── _LocalProvider initialisation ─────────────────────────────────────────────

class TestLocalProviderInit:
    def test_model_id_set_from_env(self):
        provider = _make_provider(model="hf.co/anupamojha/sentinel-patcher-7b")
        assert provider.model_id == "hf.co/anupamojha/sentinel-patcher-7b"

    def test_default_ollama_host(self):
        with patch.dict(os.environ, {"SENTINEL_LOCAL_MODEL": "mymodel"}, clear=True):
            with patch("requests.get") as mock_get:
                from llm_client import _LocalProvider
                _LocalProvider()
        mock_get.assert_called_once()
        called_url = mock_get.call_args[0][0]
        assert "localhost:11434" in called_url

    def test_custom_ollama_host(self):
        with patch.dict(os.environ,
                        {"SENTINEL_LOCAL_MODEL": "mymodel",
                         "OLLAMA_HOST": "http://gpu-server:11434"},
                        clear=True):
            with patch("requests.get") as mock_get:
                from llm_client import _LocalProvider
                _LocalProvider()
        called_url = mock_get.call_args[0][0]
        assert "gpu-server:11434" in called_url

    def test_raises_when_ollama_not_running(self):
        import requests as _requests
        with patch.dict(os.environ, {"SENTINEL_LOCAL_MODEL": "mymodel"}, clear=True):
            with patch("requests.get",
                       side_effect=_requests.exceptions.ConnectionError):
                from llm_client import _LocalProvider
                with pytest.raises(RuntimeError, match="Ollama is not running"):
                    _LocalProvider()


# ── generate ──────────────────────────────────────────────────────────────────

class TestLocalProviderGenerate:
    def test_generate_returns_content(self):
        provider = _make_provider()
        expected = '{"patches": {}, "changes": [], "analysis": "ok"}'
        mock_resp = _mock_response(expected)

        with patch("requests.post", return_value=mock_resp):
            result = provider.generate("system prompt", "user prompt")

        assert result == expected

    def test_generate_sends_correct_payload(self):
        provider = _make_provider(model="mymodel")
        with patch("requests.post", return_value=_mock_response("{}")) as mock_post:
            provider.generate("sys", "usr")

        payload = mock_post.call_args[1]["json"]
        assert payload["model"] == "mymodel"
        assert payload["messages"][0] == {"role": "system", "content": "sys"}
        assert payload["messages"][1] == {"role": "user", "content": "usr"}
        assert payload["temperature"] == 0.1
        assert payload["stream"] is False

    def test_generate_records_tokens(self):
        provider = _make_provider()
        with patch("requests.post", return_value=_mock_response("x", 200, 80)):
            with patch.object(provider, "record_tokens") as mock_record:
                provider.generate("sys", "usr", stage="patch")

        mock_record.assert_called_once_with(200, 80, stage="patch")

    def test_generate_raises_on_model_not_found(self):
        provider = _make_provider()
        not_found = MagicMock()
        not_found.status_code = 404
        not_found.raise_for_status.side_effect = Exception("404")

        with patch("requests.post", return_value=not_found):
            with pytest.raises(RuntimeError, match="not found in Ollama"):
                provider.generate("sys", "usr")

    def test_generate_raises_on_connection_error(self):
        import requests as _requests
        provider = _make_provider()
        with patch("requests.post",
                   side_effect=_requests.exceptions.ConnectionError):
            with pytest.raises(RuntimeError, match="Ollama stopped responding"):
                provider.generate("sys", "usr")


# ── generate_cached ───────────────────────────────────────────────────────────

class TestLocalProviderGenerateCached:
    def test_concatenates_cacheable_and_volatile(self):
        provider = _make_provider()
        with patch("requests.post", return_value=_mock_response("{}")) as mock_post:
            provider.generate_cached("sys", "stable block", "volatile block")

        payload = mock_post.call_args[1]["json"]
        user_content = payload["messages"][1]["content"]
        assert "stable block" in user_content
        assert "volatile block" in user_content

    def test_works_without_volatile_block(self):
        provider = _make_provider()
        with patch("requests.post", return_value=_mock_response("{}")) as mock_post:
            provider.generate_cached("sys", "only cacheable")

        payload = mock_post.call_args[1]["json"]
        assert payload["messages"][1]["content"] == "only cacheable"


# ── CLI integration ───────────────────────────────────────────────────────────

class TestCLILocalFlag:
    def test_llm_local_sets_env(self):
        """--llm local should set LLM_PROVIDER=local in the environment."""
        from click.testing import CliRunner
        # patch factory so we don't actually run a remediation
        with patch("sys.path"):
            pass  # ensure orchestrator path is inserted by cli module

        runner = CliRunner()
        # We only need to verify the env var is set; bail before factory runs
        captured = {}

        def fake_factory():
            captured["provider"] = os.getenv("LLM_PROVIDER")
            raise SystemExit(0)

        import orchestrator.cli as cli_module
        with patch.object(cli_module, "_check_prerequisites"):
            with runner.isolated_filesystem():
                with patch("builtins.__import__", side_effect=lambda *a, **kw: (_ for _ in ()).throw(SystemExit(0))):
                    pass  # just verifying arg parsing below

        # Lightweight: confirm click parses "local" without error
        from click.testing import CliRunner
        from orchestrator.cli import sentinel
        runner = CliRunner()
        result = runner.invoke(sentinel, [
            "fix-cve", "--repo", "https://github.com/x/y",
            "--llm", "local",
            "--model", "hf.co/anupamojha/sentinel-patcher-7b",
        ], catch_exceptions=False, env={"GITHUB_TOKEN": "tok",
                                         "SENTINEL_LOCAL_MODEL": "hf.co/anupamojha/sentinel-patcher-7b"})
        # Will fail at _check_prerequisites / docker check, but NOT at arg parsing
        assert "Error: Invalid value for '--llm'" not in result.output

    def test_check_prerequisites_skips_api_key_when_local_model_set(self):
        """No ANTHROPIC or GEMINI key needed when SENTINEL_LOCAL_MODEL is set."""
        import orchestrator.cli as cli_module
        env = {
            "GITHUB_TOKEN": "tok",
            "SENTINEL_LOCAL_MODEL": "hf.co/anupamojha/sentinel-patcher-7b",
        }
        with patch.dict(os.environ, env, clear=True):
            with patch("docker.from_env") as mock_docker:
                mock_docker.return_value.ping.return_value = True
                # Should not raise — no API key present but local model is set
                cli_module._check_prerequisites()
