"""Unit tests for config loader — run by Sentinel's verify step after patching."""
import pytest
import yaml
from app.config import load_env_override, load_all_configs


def test_load_env_override_basic_types():
    result = load_env_override("key: value\nnumber: 42")
    assert result == {"key": "value", "number": 42}


def test_load_env_override_empty_string():
    assert load_env_override("") == {}


def test_load_env_override_nested():
    yaml_str = """
database:
  host: localhost
  port: 5432
"""
    result = load_env_override(yaml_str)
    assert result["database"]["host"] == "localhost"
    assert result["database"]["port"] == 5432


def test_load_all_configs_returns_dict(tmp_path):
    cfg_file = tmp_path / "extra.yaml"
    cfg_file.write_text("extra_key: extra_value\n")
    merged = load_all_configs(str(cfg_file))
    assert isinstance(merged, dict)
