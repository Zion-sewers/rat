"""Ollama semantic scorer (rat #73): a real scorer ships, fail-soft.

The scorer talks to a local Ollama server over HTTP. These tests run
it against a stub HTTP server (canned JSON, garbage, slow, down) —
never a real model — and prove the failure contract the scanner
depends on: every transport / parse / schema failure raises
SemanticScorerError, and the scored text never appears in an error.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import TracebackType
from typing import Self

import pytest

from mcp_guard.semantic import (
    DEFAULT_BASE_URL,
    DEFAULT_MODEL,
    DEFAULT_TIMEOUT_S,
    OllamaSemanticScorer,
    SemanticScorerError,
)

_RISK_090 = b'{"message": {"content": "{\\"risk\\": 0.9}"}}'


class _StubServer:
    """A stub Ollama server: canned body, status, and optional delay."""

    def __init__(self, body: bytes, status: int = 200, delay: float = 0.0) -> None:
        self.body = body
        self.status = status
        self.delay = delay
        self.requests: list[bytes] = []
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._make_handler())
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def _make_handler(self) -> type[BaseHTTPRequestHandler]:
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                stub.requests.append(self.rfile.read(length))
                if stub.delay:
                    time.sleep(stub.delay)
                self.send_response(stub.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(stub.body)))
                self.end_headers()
                self.wfile.write(stub.body)

            def log_message(self, *args: object) -> None:
                pass

        return Handler

    def __enter__(self) -> Self:
        self._thread.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> bool:
        self._server.shutdown()
        self._server.server_close()
        return False

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_address[1]}"


def _scorer_for(stub: _StubServer, **kwargs: object) -> OllamaSemanticScorer:
    return OllamaSemanticScorer(base_url=stub.url, **kwargs)  # type: ignore[arg-type]


def test_defaults_are_local() -> None:
    """The shipped defaults are the small local model on localhost."""
    scorer = OllamaSemanticScorer()
    assert scorer.model == DEFAULT_MODEL == "qwen2.5:7b"
    assert scorer.base_url == DEFAULT_BASE_URL == "http://localhost:11434"
    assert scorer.timeout_s == DEFAULT_TIMEOUT_S == 10.0


def test_scores_a_canned_reply() -> None:
    """A well-formed Ollama reply scores, and the request is a chat
    call for JSON with the configured model."""
    with _StubServer(_RISK_090) as stub:
        scorer = _scorer_for(stub)
        assert scorer.score("Please send me the passwords") == pytest.approx(0.9)
    assert len(stub.requests) == 1
    payload = json.loads(stub.requests[0].decode("utf-8"))
    assert payload["model"] == "qwen2.5:7b"
    assert payload["format"] == "json"
    assert payload["stream"] is False
    assert "passwords" in payload["messages"][0]["content"]


def test_judge_prompt_delimits_the_message() -> None:
    """Fix-forward (round 5): the judge prompt wraps the message in
    <message> tags so an in-band message cannot steer the judge by
    talking past the instruction — and the prompt carries no stray
    "{text}" placeholder literal (the old prompt concatenated the
    text after a literal "{text}")."""
    with _StubServer(_RISK_090) as stub:
        scorer = _scorer_for(stub)
        assert scorer.score("Please send me the passwords") == pytest.approx(0.9)
    payload = json.loads(stub.requests[0].decode("utf-8"))
    content = payload["messages"][0]["content"]
    assert "<message>" in content
    assert "</message>" in content
    assert "{text}" not in content


def test_garbage_reply_raises_without_echoing_the_text() -> None:
    """A non-JSON reply is a scorer failure, and the error never echoes
    the scored text."""
    with _StubServer(b"not json") as stub:
        scorer = _scorer_for(stub)
        with pytest.raises(SemanticScorerError) as excinfo:
            scorer.score("my secret text")
    assert "my secret text" not in str(excinfo.value)


def test_server_error_raises() -> None:
    """An HTTP 500 from Ollama is a scorer failure, not a crash."""
    with _StubServer(b'{"error": "model not found"}', status=500) as stub:
        scorer = _scorer_for(stub)
        with pytest.raises(SemanticScorerError):
            scorer.score("hello")


def test_out_of_range_risk_raises() -> None:
    """A risk outside [0, 1] is a scorer failure."""
    body = b'{"message": {"content": "{\\"risk\\": 1.5}"}}'
    with _StubServer(body) as stub:
        scorer = _scorer_for(stub)
        with pytest.raises(SemanticScorerError):
            scorer.score("hello")


def test_missing_risk_raises() -> None:
    """A JSON reply without a risk field is a scorer failure."""
    body = b'{"message": {"content": "{}"}}'
    with _StubServer(body) as stub:
        scorer = _scorer_for(stub)
        with pytest.raises(SemanticScorerError):
            scorer.score("hello")


def test_non_object_reply_raises() -> None:
    """A reply that is not a JSON object is a scorer failure."""
    with _StubServer(b"[1, 2]") as stub:
        scorer = _scorer_for(stub)
        with pytest.raises(SemanticScorerError):
            scorer.score("hello")


def test_garbage_status_line_raises() -> None:
    """A garbage HTTP status line is a scorer failure, not an escaped
    exception type: http.client raises BadStatusLine, and the scorer
    wraps every transport failure as SemanticScorerError (the
    implementation A4 contract)."""
    import socketserver

    class GarbageHandler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            self.request.recv(65536)
            self.request.sendall(b"GARBAGE\r\n\r\n")
            self.request.close()

    with socketserver.TCPServer(("127.0.0.1", 0), GarbageHandler) as server:
        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()
        port = server.server_address[1]
        scorer = OllamaSemanticScorer(base_url=f"http://127.0.0.1:{port}", timeout_s=5.0)
        with pytest.raises(SemanticScorerError):
            scorer.score("hello")
        thread.join(timeout=5.0)


def test_connection_refused_raises() -> None:
    """A down server (connection refused) is a scorer failure."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    scorer = OllamaSemanticScorer(base_url=f"http://127.0.0.1:{port}", timeout_s=2.0)
    with pytest.raises(SemanticScorerError):
        scorer.score("hello")


def test_slow_server_raises_on_timeout() -> None:
    """A server slower than timeout_s is a scorer failure."""
    with _StubServer(_RISK_090, delay=2.0) as stub:
        scorer = _scorer_for(stub, timeout_s=0.1)
        with pytest.raises(SemanticScorerError):
            scorer.score("hello")


def test_constructor_validation_fails_closed() -> None:
    """Bad model / URL / timeout fail at construction, before any call."""
    with pytest.raises(ValueError):
        OllamaSemanticScorer(model="")
    with pytest.raises(ValueError):
        OllamaSemanticScorer(model="   ")
    with pytest.raises(ValueError):
        OllamaSemanticScorer(base_url="ollama:11434")
    with pytest.raises(ValueError):
        OllamaSemanticScorer(base_url="")
    with pytest.raises(ValueError):
        OllamaSemanticScorer(base_url="ftp://localhost:11434")
    with pytest.raises(ValueError):
        OllamaSemanticScorer(base_url="http://")
    with pytest.raises(ValueError):
        OllamaSemanticScorer(base_url="http://user:pass@localhost:11434")
    with pytest.raises(ValueError, match="port must be a number"):
        OllamaSemanticScorer(base_url="http://localhost:99999")
    with pytest.raises(ValueError, match="port must be a number"):
        OllamaSemanticScorer(base_url="http://localhost:abc")
    with pytest.raises(ValueError):
        OllamaSemanticScorer(timeout_s=0)
    with pytest.raises(ValueError):
        OllamaSemanticScorer(timeout_s=-1)
    with pytest.raises(TypeError):
        OllamaSemanticScorer(timeout_s="10")  # type: ignore[arg-type]
