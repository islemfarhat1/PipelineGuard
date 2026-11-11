import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from assistant.client import OllamaClient, validate_local_url


@pytest.mark.parametrize("url", [
    "http://localhost:11434",
    "http://127.0.0.1:11434/",
    "http://[::1]:11434",
])
def test_loopback_urls_are_accepted(url):
    assert validate_local_url(url) == url.rstrip("/")


@pytest.mark.parametrize("url", [
    "http://example.com:11434",
    "http://192.168.1.10:11434",
    "http://127.0.0.1.evil.example:11434",
    "http://localhost.evil.example",
    "https://localhost:11434",
    "ftp://localhost",
    "http://user:password@localhost:11434",
    "localhost:11434",
])
def test_non_local_urls_are_rejected(url):
    with pytest.raises(ValueError):
        validate_local_url(url)


def test_client_refuses_remote_url():
    with pytest.raises(ValueError):
        OllamaClient("model", "http://api.example.com")


class _FakeOllama(BaseHTTPRequestHandler):
    received = []

    def do_POST(self):
        length = int(self.headers["Content-Length"])
        _FakeOllama.received.append(json.loads(self.rfile.read(length)))
        body = json.dumps({"response": '{"ok": true}'}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def test_generate_sends_deterministic_request_and_ignores_proxy(monkeypatch):
    # A proxy that does not exist: if the client used it, the call would fail.
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:9")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)

    server = HTTPServer(("127.0.0.1", 0), _FakeOllama)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _FakeOllama.received.clear()

    try:
        client = OllamaClient(
            "qwen-test", f"http://127.0.0.1:{server.server_port}", timeout=5
        )
        text = client.generate("system", "prompt", {"type": "object"})
    finally:
        server.shutdown()

    assert text == '{"ok": true}'
    payload = _FakeOllama.received[0]
    assert payload["model"] == "qwen-test"
    assert payload["stream"] is False
    assert payload["format"] == {"type": "object"}
    assert payload["options"]["temperature"] == 0
