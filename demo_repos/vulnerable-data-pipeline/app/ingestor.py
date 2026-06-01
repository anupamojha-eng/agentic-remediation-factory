"""
HTTP data ingestor — fetches remote datasets and processes images.

Uses requests (vulnerable: GHSA-j8r2-6x86-q33q) and Pillow (multiple CVEs).
Vulnerabilities here are at the dependency level; no source-code pattern fix
is needed — Sentinel resolves them via requirements.txt version bumps only.
"""
import io
import requests
from PIL import Image, ImageFilter


def fetch_json(url: str, auth_token: str = None) -> dict:
    """
    Fetch a JSON dataset from a remote URL.

    GHSA-j8r2-6x86-q33q: if `url` redirects to a different host, requests
    < 2.31.0 forwards the Authorization header to the redirected host,
    leaking credentials to a third-party server.
    """
    headers = {}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    return resp.json()


def fetch_image(url: str) -> Image.Image:
    """
    Download and decode an image from a remote URL.

    Pillow < 9.0 has multiple heap-buffer-overflow CVEs in the TIFF and
    BMP parsers (GHSA-4fx9-vc88-q2xc, GHSA-8vj2-vxx3-667w).  A crafted
    image from an attacker-controlled URL can trigger RCE in the decoder.
    """
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    return Image.open(io.BytesIO(resp.content))


def thumbnail(image: Image.Image, size: tuple[int, int] = (256, 256)) -> Image.Image:
    """Resize an image to a thumbnail, applying a soft blur."""
    img = image.copy()
    img.thumbnail(size, Image.LANCZOS)
    return img.filter(ImageFilter.SMOOTH)


def process_batch(urls: list[str], auth_token: str = None) -> list[dict]:
    """Download and summarise a batch of remote resources."""
    results = []
    for url in urls:
        try:
            if url.endswith((".png", ".jpg", ".jpeg", ".tiff", ".bmp")):
                img = fetch_image(url)
                results.append({"url": url, "type": "image", "size": img.size})
            else:
                data = fetch_json(url, auth_token)
                results.append({"url": url, "type": "json", "keys": list(data.keys())})
        except Exception as exc:
            results.append({"url": url, "error": str(exc)})
    return results
