#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Gandon-PRO MCP server.

Exposes the native gandon_core analysis engine (the same code the
Gandon-PRO GUI uses: disassembly, control flow, xrefs, strings, imports,
a decompiler and byte-pattern search) as MCP tools, so an MCP client
(Claude Desktop, Claude Code, a remote Claude session over a network
connector, or any MCP-compatible client) can read and reason about a
binary.

It is a thin, stateless bridge: every tool call shells out to
gandon_mcp_backend.exe, which loads the binary, runs ONE analysis command
and prints a single JSON object to stdout. This server only remembers the
"current" binary path (gandon_set_target) so most tools do not need to
repeat it on every call.

No third-party dependencies: only the Python standard library.

Two transports, picked with a flag:

  stdio (default) - for Claude Desktop / Claude Code on the SAME machine,
  spawned as a child process:
      python gandon_mcp_server.py [--backend path\\to\\gandon_mcp_backend.exe]

  HTTP (Streamable HTTP, MCP 2025-03-26) - listens on a TCP port so a
  REMOTE client (e.g. this machine's own Gandon-PRO exposed to a cloud
  Claude session via a tunnel/port-forward) can connect over the network:
      python gandon_mcp_server.py --http --port 8765 [--token SECRET]

  Single endpoint: POST http://<host>:<port>/mcp (JSON-RPC body).
  GET  http://<host>:<port>/health is a plain liveness check.

Protocol: MCP 2024-11-05 JSON-RPC, newline-delimited over stdio or as the
POST body over HTTP.
"""
from __future__ import annotations

import argparse
import json
import secrets
import subprocess
import sys
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "gandon-pro"
SERVER_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Backend process wrapper
# ---------------------------------------------------------------------------


class BackendError(Exception):
    pass


class Backend:
    def __init__(self, exe_path: Path):
        self.exe_path = exe_path
        self.current_binary: str | None = None

    def run(self, binary: str, command: str, *args: str) -> dict:
        if not self.exe_path.exists():
            raise BackendError(f"gandon_mcp_backend.exe not found at {self.exe_path}")
        if not binary:
            raise BackendError(
                "No binary selected. Call gandon_set_target first, or pass a 'path'."
            )
        resolved = str(Path(binary).expanduser())
        if not Path(resolved).exists():
            raise BackendError(f"File not found: {resolved}")
        cmd = [str(self.exe_path), resolved, command, *args]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120, encoding="utf-8", errors="replace"
            )
        except subprocess.TimeoutExpired:
            raise BackendError(f"gandon_mcp_backend timed out running: {command}")
        if not proc.stdout.strip():
            raise BackendError(
                f"gandon_mcp_backend produced no output (exit {proc.returncode}). "
                f"stderr: {proc.stderr.strip()[:500]}"
            )
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise BackendError(f"Could not parse backend output as JSON: {exc}. Raw: {proc.stdout[:500]}")
        if not data.get("ok", False):
            raise BackendError(data.get("error", "unknown backend error"))
        return data

    def target(self, explicit: str | None) -> str:
        path = explicit or self.current_binary
        if not path:
            raise BackendError(
                "No binary selected. Call gandon_set_target(path=...) first, or pass 'path' to this tool."
            )
        return path


# ---------------------------------------------------------------------------
# Tool definitions: (name, description, input schema, handler)
# ---------------------------------------------------------------------------

ADDR_DESC = "Address (hex like 0x140001000 or decimal), a function name, an import/export name, or a renamed label."


def _schema(properties: dict, required: list[str] | None = None) -> dict:
    return {"type": "object", "properties": properties, "required": required or []}


PATH_PROP = {"path": {"type": "string", "description": "Binary to analyze. Optional once gandon_set_target was called."}}


def build_tools(backend: Backend) -> dict[str, dict]:
    """Returns {tool_name: {"description":..., "inputSchema":..., "handler": fn}}."""

    def h_set_target(args: dict) -> dict:
        path = args.get("path")
        if not path:
            raise BackendError("'path' is required")
        resolved = str(Path(path).expanduser())
        if not Path(resolved).exists():
            raise BackendError(f"File not found: {resolved}")
        backend.current_binary = resolved
        info = backend.run(resolved, "info")
        info.pop("ok", None)
        return {"target": resolved, **info}

    def h_info(args: dict) -> dict:
        data = backend.run(backend.target(args.get("path")), "info")
        data.pop("ok", None)
        return data

    def h_functions(args: dict) -> dict:
        limit = str(args.get("limit", 200))
        data = backend.run(backend.target(args.get("path")), "functions", limit)
        data.pop("ok", None)
        return data

    def h_disasm(args: dict) -> dict:
        address = args.get("address")
        if not address:
            raise BackendError("'address' is required")
        count = str(args.get("count", 40))
        data = backend.run(backend.target(args.get("path")), "disasm", str(address), count)
        data.pop("ok", None)
        return data

    def h_listing(args: dict) -> dict:
        address = args.get("address")
        if not address:
            raise BackendError("'address' is required")
        data = backend.run(backend.target(args.get("path")), "listing", str(address))
        data.pop("ok", None)
        return data

    def h_decompile(args: dict) -> dict:
        address = args.get("address")
        if not address:
            raise BackendError("'address' is required (a function start, name, or any address inside it)")
        comments = "1" if args.get("address_comments") else "0"
        data = backend.run(backend.target(args.get("path")), "decompile", str(address), comments)
        data.pop("ok", None)
        return data

    def h_xrefs(args: dict) -> dict:
        address = args.get("address")
        if not address:
            raise BackendError("'address' is required")
        direction = args.get("direction", "to")
        if direction not in ("to", "from"):
            raise BackendError("'direction' must be 'to' or 'from'")
        data = backend.run(backend.target(args.get("path")), f"xrefs_{direction}", str(address))
        data.pop("ok", None)
        return data

    def h_strings(args: dict) -> dict:
        min_length = str(args.get("min_length", 5))
        data = backend.run(backend.target(args.get("path")), "strings", min_length)
        data.pop("ok", None)
        return data

    def h_imports(args: dict) -> dict:
        data = backend.run(backend.target(args.get("path")), "imports")
        data.pop("ok", None)
        return data

    def h_exports(args: dict) -> dict:
        data = backend.run(backend.target(args.get("path")), "exports")
        data.pop("ok", None)
        return data

    def h_resources(args: dict) -> dict:
        data = backend.run(backend.target(args.get("path")), "resources")
        data.pop("ok", None)
        return data

    def h_segments(args: dict) -> dict:
        data = backend.run(backend.target(args.get("path")), "segments")
        data.pop("ok", None)
        return data

    def h_hex(args: dict) -> dict:
        address = args.get("address")
        if not address:
            raise BackendError("'address' is required")
        rows = str(args.get("rows", 16))
        data = backend.run(backend.target(args.get("path")), "hex", str(address), rows)
        data.pop("ok", None)
        return data

    def h_search_bytes(args: dict) -> dict:
        pattern = args.get("pattern")
        if not pattern:
            raise BackendError("'pattern' is required, e.g. '55 8B EC ?? ??'")
        data = backend.run(backend.target(args.get("path")), "search_bytes", pattern)
        data.pop("ok", None)
        return data

    def h_search_text(args: dict) -> dict:
        text = args.get("text")
        if not text:
            raise BackendError("'text' is required")
        data = backend.run(backend.target(args.get("path")), "search_text", text)
        data.pop("ok", None)
        return data

    def h_auto_analysis(args: dict) -> dict:
        data = backend.run(backend.target(args.get("path")), "auto_analysis")
        data.pop("ok", None)
        return data

    def h_call_graph(args: dict) -> dict:
        address = args.get("address")
        if not address:
            raise BackendError("'address' is required")
        depth = str(args.get("depth", 2))
        data = backend.run(backend.target(args.get("path")), "call_graph", str(address), depth)
        data.pop("ok", None)
        return data

    def h_patch_bytes(args: dict) -> dict:
        address = args.get("address")
        new_bytes = args.get("bytes")
        out_path = args.get("out_path")
        if not address or not new_bytes or not out_path:
            raise BackendError("'address', 'bytes' and 'out_path' are all required")
        # Never silently overwrite the original file: refuse if out_path == source.
        source = backend.target(args.get("path"))
        if Path(out_path).expanduser().resolve() == Path(source).expanduser().resolve():
            raise BackendError("out_path must differ from the source binary; this tool never overwrites the original.")
        data = backend.run(source, "patch_bytes", str(address), new_bytes, out_path)
        data.pop("ok", None)
        return data

    return {
        "gandon_set_target": {
            "description": (
                "Select the binary all other gandon_* tools operate on by default. "
                "Returns basic info (format, architecture, entry point, function count) to confirm it loaded."
            ),
            "inputSchema": _schema(
                {"path": {"type": "string", "description": "Full path to the .exe/.dll/.so/.elf to analyze."}},
                ["path"],
            ),
            "handler": h_set_target,
        },
        "gandon_info": {
            "description": "Basic facts about the binary: format, architecture, bitness, image base, entry point, sections, function/xref counts.",
            "inputSchema": _schema(PATH_PROP),
            "handler": h_info,
        },
        "gandon_list_functions": {
            "description": "List discovered functions with their start address, name and instruction count.",
            "inputSchema": _schema({**PATH_PROP, "limit": {"type": "integer", "description": "Max functions to return (default 200)."}}),
            "handler": h_functions,
        },
        "gandon_disasm": {
            "description": "Disassemble instructions starting at an address, as a compact instruction list (address, raw bytes, mnemonic + operands).",
            "inputSchema": _schema(
                {**PATH_PROP, "address": {"type": "string", "description": ADDR_DESC}, "count": {"type": "integer", "description": "Instructions to decode (default 40)."}},
                ["address"],
            ),
            "handler": h_disasm,
        },
        "gandon_listing": {
            "description": "Full IDA-style text listing (addresses, labels, comments, xref annotations) for the function containing an address.",
            "inputSchema": _schema({**PATH_PROP, "address": {"type": "string", "description": ADDR_DESC}}, ["address"]),
            "handler": h_listing,
        },
        "gandon_decompile": {
            "description": "Decompile one function (x86/x64 only) to C-like pseudocode. This is usually the fastest way to understand a crackme check.",
            "inputSchema": _schema(
                {**PATH_PROP, "address": {"type": "string", "description": ADDR_DESC}, "address_comments": {"type": "boolean", "description": "Prefix each statement with its source address."}},
                ["address"],
            ),
            "handler": h_decompile,
        },
        "gandon_xrefs": {
            "description": "List cross-references to or from an address (calls, jumps, data references), each with the symbolic name of both ends.",
            "inputSchema": _schema(
                {**PATH_PROP, "address": {"type": "string", "description": ADDR_DESC}, "direction": {"type": "string", "enum": ["to", "from"], "description": "Default 'to': who references this address."}},
                ["address"],
            ),
            "handler": h_xrefs,
        },
        "gandon_strings": {
            "description": "ASCII/UTF-16 strings embedded in the binary (addresses + text). Good first step: look for prompts, 'correct'/'wrong' messages, hard-coded keys.",
            "inputSchema": _schema({**PATH_PROP, "min_length": {"type": "integer", "description": "Minimum string length (default 5)."}}),
            "handler": h_strings,
        },
        "gandon_imports": {
            "description": "Imported functions (library!name, ordinal, IAT address). Useful to spot crypto/string-compare/MessageBox-style API usage.",
            "inputSchema": _schema(PATH_PROP),
            "handler": h_imports,
        },
        "gandon_exports": {
            "description": "Exported functions/symbols of the binary.",
            "inputSchema": _schema(PATH_PROP),
            "handler": h_exports,
        },
        "gandon_resources": {
            "description": "PE resource directory as text (icons, version info, dialogs, etc. when present).",
            "inputSchema": _schema(PATH_PROP),
            "handler": h_resources,
        },
        "gandon_segments": {
            "description": "Memory segments/sections overview (name, range, permissions).",
            "inputSchema": _schema(PATH_PROP),
            "handler": h_segments,
        },
        "gandon_hex": {
            "description": "Hex dump (address, hex bytes, ASCII) starting at an address.",
            "inputSchema": _schema(
                {**PATH_PROP, "address": {"type": "string", "description": ADDR_DESC}, "rows": {"type": "integer", "description": "16-byte rows to dump (default 16)."}},
                ["address"],
            ),
            "handler": h_hex,
        },
        "gandon_search_bytes": {
            "description": "Search the file for a byte pattern with optional wildcards, e.g. '55 8B EC ?? ?? 00'. Returns matching addresses.",
            "inputSchema": _schema({**PATH_PROP, "pattern": {"type": "string", "description": "Space-separated hex bytes; '??' or '?' is a wildcard byte."}}, ["pattern"]),
            "handler": h_search_bytes,
        },
        "gandon_search_text": {
            "description": "Search the file for an exact ASCII substring. Returns matching addresses.",
            "inputSchema": _schema({**PATH_PROP, "text": {"type": "string"}}, ["text"]),
            "handler": h_search_text,
        },
        "gandon_auto_analysis": {
            "description": (
                "Run recursive-descent auto-analysis: discovers more functions from call/jump targets, "
                "names import thunks, and propagates noreturn. Run this once early on a crackme to get a "
                "complete function list before decompiling."
            ),
            "inputSchema": _schema(PATH_PROP),
            "handler": h_auto_analysis,
        },
        "gandon_call_graph": {
            "description": "Call graph edges reachable from a function, up to a given depth (default 2). Useful to see what a function calls before decompiling all of it.",
            "inputSchema": _schema(
                {**PATH_PROP, "address": {"type": "string", "description": ADDR_DESC}, "depth": {"type": "integer", "description": "Max call depth (default 2)."}},
                ["address"],
            ),
            "handler": h_call_graph,
        },
        "gandon_patch_bytes": {
            "description": (
                "Patch bytes at an address (e.g. flip a jz/jnz, NOP a check) and write the result to a NEW file "
                "(out_path). Never overwrites the source binary. 'bytes' is space-separated hex, e.g. '90 90' for two NOPs."
            ),
            "inputSchema": _schema(
                {
                    **PATH_PROP,
                    "address": {"type": "string", "description": ADDR_DESC},
                    "bytes": {"type": "string", "description": "Space-separated replacement hex bytes, e.g. '90 90' or 'EB'."},
                    "out_path": {"type": "string", "description": "Where to write the patched copy. Must differ from the source file."},
                },
                ["address", "bytes", "out_path"],
            ),
            "handler": h_patch_bytes,
        },
    }


# ---------------------------------------------------------------------------
# MCP stdio JSON-RPC server (no external dependencies)
# ---------------------------------------------------------------------------


def result_envelope(msg_id: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def error_envelope(msg_id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def tool_list_payload(tools: dict[str, dict]) -> list[dict]:
    return [
        {"name": name, "description": meta["description"], "inputSchema": meta["inputSchema"]}
        for name, meta in tools.items()
    ]


def dispatch_message(message: dict, tools: dict[str, dict]) -> dict | None:
    """Handles one JSON-RPC request/notification. Returns the response dict,
    or None when `message` was a notification (no `id`, no reply expected)."""
    method = message.get("method")
    msg_id = message.get("id")
    params = message.get("params") or {}

    if method == "initialize":
        return result_envelope(
            msg_id,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            },
        )
    if method == "notifications/initialized":
        return None
    if method == "tools/list":
        return result_envelope(msg_id, {"tools": tool_list_payload(tools)})
    if method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments") or {}
        tool = tools.get(name)
        if tool is None:
            return result_envelope(msg_id, {"content": [{"type": "text", "text": f"Unknown tool: {name}"}], "isError": True})
        try:
            result = tool["handler"](arguments)
            text = json.dumps(result, ensure_ascii=False, indent=2)
            return result_envelope(msg_id, {"content": [{"type": "text", "text": text}], "isError": False})
        except BackendError as exc:
            return result_envelope(msg_id, {"content": [{"type": "text", "text": str(exc)}], "isError": True})
        except Exception as exc:  # defensive: never crash the server on a bad call
            return result_envelope(msg_id, {"content": [{"type": "text", "text": f"Internal error: {exc}"}], "isError": True})
    if method == "ping":
        return result_envelope(msg_id, {})
    if msg_id is not None:
        return error_envelope(msg_id, -32601, f"Method not found: {method}")
    return None  # unknown notification: ignore


# ---------------------------------------------------------------------------
# Transport 1: stdio (newline-delimited JSON-RPC) - local child process
# ---------------------------------------------------------------------------


def run_stdio_server(backend: Backend) -> None:
    tools = build_tools(backend)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        response = dispatch_message(message, tools)
        if response is not None:
            sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
            sys.stdout.flush()


# ---------------------------------------------------------------------------
# Transport 2: Streamable HTTP - network port, for a remote MCP client
# ---------------------------------------------------------------------------


def make_http_handler(backend: Backend, token: str | None):
    tools = build_tools(backend)

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = f"{SERVER_NAME}-mcp/{SERVER_VERSION}"

        def log_message(self, fmt: str, *args) -> None:  # quieter default logging
            sys.stderr.write("[gandon-mcp] " + (fmt % args) + "\n")

        def _authorized(self) -> bool:
            if not token:
                return True
            header = self.headers.get("Authorization", "")
            return header == f"Bearer {token}"

        def _send_json(self, status: int, payload: dict | None, extra_headers: dict | None = None) -> None:
            body = b"" if payload is None else json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            for key, value in (extra_headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            if body:
                self.wfile.write(body)

        def do_OPTIONS(self) -> None:  # CORS preflight
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, Mcp-Session-Id")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_GET(self) -> None:
            if self.path.rstrip("/") == "/health":
                self._send_json(200, {"status": "ok", "server": SERVER_NAME, "version": SERVER_VERSION})
                return
            self._send_json(404, {"error": "not found; POST JSON-RPC to /mcp"})

        def do_POST(self) -> None:
            if self.path.rstrip("/") != "/mcp":
                self._send_json(404, {"error": "unknown endpoint; use /mcp"})
                return
            if not self._authorized():
                self._send_json(401, {"error": "missing or invalid bearer token"})
                return
            length = int(self.headers.get("Content-Length", "0") or "0")
            raw = self.rfile.read(length) if length else b""
            try:
                message = json.loads(raw.decode("utf-8")) if raw else {}
            except (json.JSONDecodeError, UnicodeDecodeError):
                self._send_json(400, error_envelope(None, -32700, "Parse error"))
                return

            session_header = {}
            if isinstance(message, dict) and message.get("method") == "initialize":
                session_header = {"Mcp-Session-Id": uuid.uuid4().hex}

            if isinstance(message, list):  # batch request
                responses = [r for r in (dispatch_message(m, tools) for m in message if isinstance(m, dict)) if r is not None]
                if not responses:
                    self._send_json(202, None)
                    return
                self._send_json(200, responses, session_header)
                return

            if not isinstance(message, dict):
                self._send_json(400, error_envelope(None, -32600, "Invalid request"))
                return

            response = dispatch_message(message, tools)
            if response is None:
                self._send_json(202, None)  # notification: Accepted, no body
                return
            self._send_json(200, response, session_header)

    return Handler


def run_http_server(backend: Backend, host: str, port: int, token: str | None) -> None:
    handler = make_http_handler(backend, token)
    httpd = ThreadingHTTPServer((host, port), handler)
    url = f"http://{host}:{port}/mcp"
    print(f"[gandon-mcp] Streamable HTTP server listening on {url}", file=sys.stderr)
    if token:
        print("[gandon-mcp] Authorization required: Bearer <token>", file=sys.stderr)
    else:
        print("[gandon-mcp] WARNING: no --token set - anyone who can reach this port can read/patch files "
              "this process can access. Set --token, and never bind 0.0.0.0 without one.", file=sys.stderr)
    print(f"[gandon-mcp] Health check: http://{host}:{port}/health", file=sys.stderr)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


def main() -> None:
    parser = argparse.ArgumentParser(description="Gandon-PRO MCP server")
    default_backend = Path(__file__).resolve().parent.parent / "build-cross" / "gandon_mcp_backend.exe"
    parser.add_argument("--backend", default=str(default_backend), help="Path to gandon_mcp_backend.exe")
    parser.add_argument("--target", default=None, help="Optional binary to select on startup")
    parser.add_argument("--http", action="store_true", help="Serve over HTTP (Streamable HTTP) instead of stdio.")
    parser.add_argument("--host", default="127.0.0.1", help="HTTP bind address (default 127.0.0.1; use 0.0.0.0 for LAN/tunnel access).")
    parser.add_argument("--port", type=int, default=8765, help="HTTP port (default 8765).")
    parser.add_argument("--token", default=None, help="Bearer token required on every HTTP request. "
                                                        "Pass 'auto' to generate and print a random one.")
    args = parser.parse_args()

    backend = Backend(Path(args.backend))
    if args.target:
        backend.current_binary = str(Path(args.target).expanduser())

    if args.http:
        token = args.token
        if token == "auto":
            token = secrets.token_urlsafe(24)
            print(f"[gandon-mcp] Generated token: {token}", file=sys.stderr)
        run_http_server(backend, args.host, args.port, token)
    else:
        run_stdio_server(backend)


if __name__ == "__main__":
    main()
