"""Stdio MCP transport — spawns server subprocess and communicates via JSON-RPC."""

from __future__ import annotations

import json
import queue
import subprocess  # nosec B404 - stdio subprocess spawning is the transport's entire purpose
import threading
from types import TracebackType
from typing import IO, Any, Self, cast

JsonDict = dict[str, Any]
"""A JSON-RPC message or result object. Values are dynamically shaped per
method, so the boundary type stays permissive while every field access in
typed code goes through declared JsonDict locals (never bare ``dict``)."""


class StdioTransport:
    def __init__(self, command: list[str], timeout: float = 10.0):
        self._command = command
        self._timeout = timeout
        self._proc: subprocess.Popen[str] | None = None
        self._request_id = 0
        # Flight recorder (mcp-guard#65): the exact envelope of the most
        # recent request send plus the id of its response. The independent
        # channel for fault-delivery verification — the fuzzer checks the
        # envelope against the intended call and the response id against the
        # request id, instead of trusting the response channel alone.
        self._last_request: JsonDict | None = None
        self._last_response_id: Any = None

    def last_exchange(self) -> tuple[JsonDict | None, Any]:
        """Flight recorder: (last request envelope, last response id).

        The response id is None when no response arrived for the last send
        (timeout, crash, closed connection). Only the most recent exchange
        is kept: the engine reads it immediately after each call_tool, and
        the fuzzer is strictly serial, so one envelope is enough.
        """
        return self._last_request, self._last_response_id

    def start(self) -> None:
        self._proc = subprocess.Popen(  # nosec B603 - spawns the operator's own MCP server command
            self._command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self._initialize()

    def stop(self) -> None:
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()

    def __enter__(self) -> Self:
        self.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.stop()

    @property
    def is_alive(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def _require_streams(self) -> tuple[IO[str], IO[str]]:
        """Return (stdin, stdout) or raise ConnectionError.

        Replaces bare asserts for stream narrowing: asserts vanish under
        ``python -O``, but a dead server stream must always raise here.

        Deliberate semantic (not just a typing cleanup): unlike the old
        asserts, this also requires the server to be *alive*. A terminated
        server may still have buffered stdout, but that output is
        untrustworthy (it may answer an earlier request — response ids are
        not matched), so we fail loudly instead of returning it.
        """
        proc = self._proc
        if proc is None or not self.is_alive:
            raise ConnectionError("Server not running")
        if proc.stdin is None or proc.stdout is None:
            raise ConnectionError("Server streams unavailable")
        return proc.stdin, proc.stdout

    def _send(self, method: str, params: JsonDict | None = None) -> JsonDict:
        stdin, _ = self._require_streams()

        self._request_id += 1
        request: JsonDict = {
            "jsonrpc": "2.0",
            "id": self._request_id,
            "method": method,
        }
        if params is not None:
            request["params"] = params

        line = json.dumps(request) + "\n"
        stdin.write(line)
        stdin.flush()
        self._last_request = request
        self._last_response_id = None

        return self._read_response()

    def _notify(self, method: str, params: JsonDict | None = None) -> None:
        stdin, _ = self._require_streams()

        notification: JsonDict = {
            "jsonrpc": "2.0",
            "method": method,
        }
        if params is not None:
            notification["params"] = params

        line = json.dumps(notification) + "\n"
        stdin.write(line)
        stdin.flush()

    def _read_response(self) -> JsonDict:
        _, stdout = self._require_streams()

        q: queue.Queue[str | None] = queue.Queue()

        def _read_line() -> None:
            try:
                q.put(stdout.readline())
            except (OSError, ValueError):  # stream closed/torn down mid-read
                q.put(None)

        thread = threading.Thread(target=_read_line, daemon=True)
        thread.start()
        thread.join(timeout=self._timeout)

        if thread.is_alive():
            if self._proc and self._proc.poll() is None:
                self._proc.kill()
            raise TimeoutError(f"No response from server within {self._timeout}s timeout")

        response_line = q.get()
        if not response_line:
            raise ConnectionError("Server closed connection")
        try:
            response: JsonDict = json.loads(response_line)
        except json.JSONDecodeError:
            raise ConnectionError("Invalid JSON response from server")
        # Record the response id before any validation raises: the fuzzer's
        # delivery check needs the id even when the response is malformed in
        # other ways. A response without an id leaves the id as None.
        self._last_response_id = response.get("id")
        if "method" in response and "id" not in response:
            raise ConnectionError("Invalid JSON response from server")
        if "error" in response:
            raise RuntimeError(f"MCP error: {response['error']}")
        return cast("JsonDict", response.get("result", {}))

    def _initialize(self) -> JsonDict:
        result = self._send(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "mcp-guard", "version": "0.2.1"},
            },
        )
        self._notify("notifications/initialized")
        return result

    def list_tools(self) -> list[JsonDict]:
        result = self._send("tools/list")
        return cast("list[JsonDict]", result.get("tools", []))

    def list_resources(self) -> list[JsonDict]:
        result = self._send("resources/list")
        return cast("list[JsonDict]", result.get("resources", []))

    def list_prompts(self) -> list[JsonDict]:
        result = self._send("prompts/list")
        return cast("list[JsonDict]", result.get("prompts", []))

    def call_tool(self, tool_name: str, arguments: JsonDict) -> JsonDict:
        return self._send(
            "tools/call",
            {
                "name": tool_name,
                "arguments": arguments,
            },
        )
