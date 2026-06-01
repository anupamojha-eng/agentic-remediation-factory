"""
In-memory session and result cache backed by serialised Python objects.

KNOWN VULNERABILITY:
  pickle.loads() on data received from an external store (Redis, memcached,
  a message queue, or a peer service) allows remote code execution if an
  attacker can write a crafted payload to the store.

  This is not limited to a specific GHSA — it is a well-known class of
  vulnerability (CWE-502: Deserialization of Untrusted Data) that Sentinel
  flags proactively via its always-check pattern list.

  Remediation options the LLM may apply:
    - Replace pickle with json / msgpack for serialisable types
    - Add a HMAC-signed envelope and verify before deserialising
    - Restrict to a safe allowlist using pickletools inspection
"""
import pickle
import hashlib
import json
from typing import Any, Optional


class ResultCache:
    """Cache for expensive pipeline computation results."""

    def __init__(self):
        self._store: dict[str, bytes] = {}

    def set(self, key: str, value: Any) -> None:
        self._store[key] = pickle.dumps(value)

    def get(self, key: str) -> Optional[Any]:
        raw = self._store.get(key)
        if raw is None:
            return None
        return pickle.loads(raw)    # UNSAFE: deserializes arbitrary bytes from internal store


class NetworkCache:
    """Cache that accepts pre-serialised payloads from a remote peer service."""

    def __init__(self):
        self._remote: dict[str, bytes] = {}

    def ingest(self, key: str, payload: bytes) -> None:
        """Store a raw payload received from the network."""
        self._remote[key] = payload

    def retrieve(self, key: str) -> Optional[Any]:
        """Deserialise and return a payload — most dangerous pattern."""
        raw = self._remote.get(key)
        if raw is None:
            return None
        # UNSAFE: deserializes attacker-controlled bytes from the network
        return pickle.loads(raw)

    def retrieve_bulk(self, keys: list[str]) -> dict[str, Any]:
        """Batch retrieval — equally dangerous."""
        return {k: pickle.loads(self._remote[k])   # UNSAFE
                for k in keys if k in self._remote}


def deserialize_checkpoint(checkpoint_bytes: bytes) -> dict:
    """
    Restore a pipeline checkpoint from bytes stored in the job queue.
    The job queue is considered an internal system but may be compromised.
    """
    return pickle.loads(checkpoint_bytes)   # UNSAFE
