# Gandon-PRO MCP server

Lets Claude (or any MCP client) read a binary through the same native
analysis engine the Gandon-PRO GUI uses: disassembly, control-flow graph,
cross-references, strings, imports/exports, a decompiler, byte/text search
and byte patching (always to a new file, never the original).

## How it works

- `build-cross\gandon_mcp_backend.exe` is a one-shot CLI: it loads a binary,
  runs one analysis command and prints a single JSON object. Source:
  `src/mcp_backend.cpp`.
- `mcp\gandon_mcp_server.py` is a small, dependency-free MCP server (stdio,
  JSON-RPC, protocol `2024-11-05`) that exposes each backend command as an
  MCP tool and shells out to the backend exe per call.

No binary stays "open": every call re-loads the file (fine for crackme-sized
binaries). `gandon_set_target` just remembers a default path so you don't have
to repeat it on every tool call.

## Tools

| Tool | What it does |
|---|---|
| `gandon_set_target` | Select the binary; returns basic info. |
| `gandon_info` | Format, architecture, entry point, sections, counts. |
| `gandon_list_functions` | Discovered functions (start, name, size). |
| `gandon_disasm` | Instructions from an address. |
| `gandon_listing` | Full IDA-style text listing of a function. |
| `gandon_decompile` | C-like pseudocode for one function (x86/x64). |
| `gandon_xrefs` | Who calls/jumps/reads an address, or what it calls. |
| `gandon_strings` | Embedded strings (prompts, "wrong password", keys...). |
| `gandon_imports` / `gandon_exports` | Import/export tables. |
| `gandon_resources` / `gandon_segments` | PE resources / memory map. |
| `gandon_hex` | Hex dump from an address. |
| `gandon_search_bytes` | Byte-pattern search with `??` wildcards. |
| `gandon_search_text` | ASCII substring search. |
| `gandon_auto_analysis` | Recursive-descent function discovery + naming. |
| `gandon_call_graph` | Call graph from a function, N levels deep. |
| `gandon_patch_bytes` | Patch bytes, write to a **new** file. |

Every tool except `gandon_set_target` accepts an optional `path`; addresses
accept hex (`0x140001000`), decimal, a function/import/export name, or a
renamed label.

## Run it as a network server (so a remote/cloud Claude session can connect)

By default the server talks stdio, which only works for a client running on
*this* machine. To let a remote MCP client (e.g. this Claude session running
in the cloud, or Claude.ai's Connectors) reach it, run it in HTTP mode:

```
python mcp\gandon_mcp_server.py --http --port 8765 --token auto
```

- `--token auto` generates and prints a random bearer token (or pass your own
  with `--token <secret>`). Every request must send
  `Authorization: Bearer <token>`.
- The endpoint is `POST http://<host>:8765/mcp`; `GET /health` is a plain
  liveness check with no auth.
- By default it binds `127.0.0.1` (only this machine can reach it). To let
  something else reach it you need either:
  - **Same LAN**: `--host 0.0.0.0` and connect to `http://<this-pc-LAN-IP>:8765/mcp`
    from a device on the same network.
  - **From the internet (e.g. a cloud Claude session)**: keep `--host 127.0.0.1`
    and expose the port with a tunnel, e.g.
    `ngrok http 8765` (or Cloudflare Tunnel / Tailscale Funnel), then use the
    `https://...ngrok.../mcp` URL it gives you.
- **Always set `--token`** before exposing the port beyond localhost - this
  server can read your files and write patched copies of binaries.

Then add it as a remote MCP connector in Claude (Settings → Connectors →
Add custom connector), using that URL and the bearer token. Once added,
reconnect/start the conversation so the `gandon_*` tools become available to
that session.

## Register it in Claude Desktop (stdio, local only)

Edit `%APPDATA%\Claude\claude_desktop_config.json` and add:

```json
{
  "mcpServers": {
    "gandon-pro": {
      "command": "python",
      "args": [
        "C:\\Users\\Vasya\\OneDrive\\Документы\\Codex\\2026-09-15\\potato-aight-config-peeled-weights-walked\\cpp\\mcp\\gandon_mcp_server.py"
      ]
    }
  }
}
```

Restart Claude Desktop. The `gandon_*` tools will show up in the tool list.

## Register it in Claude Code

```
claude mcp add gandon-pro -- python "C:\Users\Vasya\OneDrive\Документы\Codex\2026-09-15\potato-aight-config-peeled-weights-walked\cpp\mcp\gandon_mcp_server.py"
```

## Typical crackme session

1. `gandon_set_target(path="C:\\...\\crackme.exe")`
2. `gandon_auto_analysis()` — finds more functions, names import thunks.
3. `gandon_strings(min_length=4)` — look for "Correct!"/"Wrong password" etc.
4. `gandon_xrefs(address="<string address>", direction="to")` — find the
   function that reads/compares that string.
5. `gandon_decompile(address="<that function>")` — read the check in
   pseudocode.
6. If needed: `gandon_patch_bytes(...)` to flip a `jne`→`je` (or similar) and
   write a patched copy to test, without touching the original file.

## Rebuilding the backend

```
cmake --build build-local --config Release --target gandon_mcp_backend
copy build-local\Release\gandon_mcp_backend.exe build-cross\gandon_mcp_backend.exe
```

## Known limits

- Decompiler/disassembler: x86/x64 only (same limit as the rest of
  Gandon-PRO); ARM64 binaries only get raw disassembly.
- `gandon_patch_bytes` never overwrites the source file - it refuses if
  `out_path` resolves to the same file.
- Each call re-analyzes the binary from scratch (no persistent session), so
  very large binaries will be slower here than in the GUI, which caches the
  loaded database. Fine for crackme-sized files.
