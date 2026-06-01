"""REST API for the data pipeline — Flask 2.0 + Werkzeug 2.0."""
import os
from flask import Flask, request, jsonify
from .config import load_config, load_env_override
from .cache import ResultCache
from .ingestor import process_batch

app = Flask(__name__)
_cache = ResultCache()


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/config")
def get_config():
    cfg = load_config()
    override_yaml = os.environ.get("PIPELINE_OVERRIDE", "")
    if override_yaml:
        cfg.update(load_env_override(override_yaml))
    return jsonify(cfg)


@app.route("/ingest", methods=["POST"])
def ingest():
    body = request.get_json(force=True)
    urls = body.get("urls", [])
    token = body.get("auth_token")
    if not urls:
        return jsonify({"error": "urls required"}), 400

    cache_key = str(sorted(urls))
    cached = _cache.get(cache_key)
    if cached:
        return jsonify({"results": cached, "cached": True})

    results = process_batch(urls, token)
    _cache.set(cache_key, results)
    return jsonify({"results": results, "cached": False})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
