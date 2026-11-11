import json
import urllib.request
from urllib.parse import urlparse

DEFAULT_OLLAMA_URL = "http://localhost:11434"

# Only the local machine is allowed: the scanned code must never leave it.
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


def validate_local_url(url: str) -> str:
    """Accept only an http URL that points to the local machine."""

    parsed = urlparse(url)

    if parsed.scheme != "http":
        raise ValueError(f"Ollama URL must use http on loopback: {url}")

    if parsed.hostname not in LOOPBACK_HOSTS:
        raise ValueError(
            f"Ollama URL must point to the local machine: {url}"
        )

    if parsed.username or parsed.password:
        raise ValueError("Ollama URL must not contain credentials")

    return url.rstrip("/")


class OllamaClient:
    """Minimal client for the Ollama /api/generate endpoint."""

    def __init__(self, model: str, url: str = DEFAULT_OLLAMA_URL,
                 timeout: float = 300.0):
        self.model = model
        self.url = validate_local_url(url)
        self.timeout = timeout

    def generate(self, system: str, prompt: str, schema: dict) -> str:
        payload = {
            "model": self.model,
            "system": system,
            "prompt": prompt,
            "stream": False,
            # Ask Ollama to constrain the output to this JSON schema.
            "format": schema,
            # Temperature 0 and a fixed seed make answers as repeatable
            # as the model allows. They do not make them correct.
            "options": {"temperature": 0, "seed": 42},
        }

        request = urllib.request.Request(
            f"{self.url}/api/generate",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        # An empty ProxyHandler ignores HTTP_PROXY and similar variables,
        # so the request cannot be routed through another machine.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

        with opener.open(request, timeout=self.timeout) as response:
            body = json.loads(response.read().decode("utf-8"))

        text = body.get("response") if isinstance(body, dict) else None

        if not isinstance(text, str):
            raise ValueError("Unexpected Ollama response format")

        return text
