"""Unit tests for the HTTP ingestor — mocked so no real network calls."""
import pytest
from unittest.mock import patch, MagicMock
import io
from PIL import Image
from app.ingestor import process_batch, thumbnail


def _make_mock_response(json_data=None, image_bytes=None, status=200):
    mock = MagicMock()
    mock.status_code = status
    mock.raise_for_status = MagicMock()
    if json_data is not None:
        mock.json.return_value = json_data
    if image_bytes is not None:
        mock.content = image_bytes
    return mock


def _png_bytes(size=(10, 10)):
    buf = io.BytesIO()
    Image.new("RGB", size, color=(128, 64, 32)).save(buf, format="PNG")
    return buf.getvalue()


def test_process_batch_json():
    with patch("app.ingestor.requests.get") as mock_get:
        mock_get.return_value = _make_mock_response(json_data={"id": 1, "name": "test"})
        results = process_batch(["https://example.com/data.json"])
    assert len(results) == 1
    assert results[0]["type"] == "json"
    assert "id" in results[0]["keys"]


def test_process_batch_image():
    with patch("app.ingestor.requests.get") as mock_get:
        mock_get.return_value = _make_mock_response(image_bytes=_png_bytes())
        results = process_batch(["https://example.com/photo.png"])
    assert len(results) == 1
    assert results[0]["type"] == "image"
    assert results[0]["size"] == (10, 10)


def test_process_batch_error_handled():
    with patch("app.ingestor.requests.get", side_effect=Exception("timeout")):
        results = process_batch(["https://example.com/bad"])
    assert results[0]["error"] == "timeout"


def test_thumbnail_reduces_size():
    img = Image.new("RGB", (1024, 768))
    thumb = thumbnail(img, (128, 128))
    assert max(thumb.size) <= 128
