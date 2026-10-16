# MCP server as a Gandon-PRO plugin (ida-multi-mcp style)

This is the "lives inside the running tool" version, the same idea as
`ida-multi-mcp`: instead of a separate process that re-loads the binary from
scratch on every call (`gandon_mcp_backend.exe` + `gandon_mcp_server.py`,
documented in `mcp/README.md`), **`gandon_mcp_plugin.dll` runs inside
`gandon_gui.exe` itself** and serves the MCP tools straight from the
already-open, already-analyzed database:

- Your renames, comments and auto-analysis are visible to every tool call
  immediately - no re-opening the file.
- `gandon_patch_bytes` patches the *live* database and pushes a normal undo
  entry: `Ctrl+Z` / Edit > Undo Patch in the GUI reverts an edit an MCP
  client made, and vice versa.
- `gandon_navigate` jumps the open GUI's current view, so you can watch the
  tool follow along on screen.

## Build

```
cmake --build build-local --config Release --target gandon_mcp_plugin
copy build-local\Release\gandon_mcp_plugin.dll build-cross\gandon_mcp_plugin.dll
```

The DLL must sit next to `gandon_gui.exe` (that's where `Load Native DLL
Plugins` looks).

## Load it

1. Open a binary in Gandon-PRO as usual.
2. `Tools -> Plugins -> Load Native DLL Plugins`.
3. It starts listening immediately (default `http://127.0.0.1:8766/mcp`).
   `Tools -> Plugins -> MCP Server Status` reports the URL and how many
   requests it has served, in the status bar and the Output log.

Optional environment variables, set **before** launching `gandon_gui.exe`:

| Variable | Default | Meaning |
|---|---|---|
| `GANDON_MCP_PORT` | `8766` | TCP port (different from the standalone server's 8765, so both can run at once). |
| `GANDON_MCP_HOST` | `127.0.0.1` | Bind address. Use `0.0.0.0` to accept LAN connections. |
| `GANDON_MCP_TOKEN` | *(none)* | If set, every `/mcp` request must send `Authorization: Bearer <token>`. **Set this before binding anything but 127.0.0.1** - this plugin can read strings/decompile and write patches into the open session. |

```
set GANDON_MCP_TOKEN=some-secret
set GANDON_MCP_PORT=8766
gandon_gui.exe
```

Then reach it from the internet the same way as the standalone server
(ngrok / Cloudflare Tunnel / Tailscale Funnel pointed at the port), and add
`https://.../mcp` as a custom MCP connector in Claude with that bearer
token.

## Tools

Same tool family as the standalone server, but operating on the live
session (`gandon_set_target`/`path` do not exist here - there is exactly one
binary: whatever is open in the GUI):

`gandon_info`, `gandon_resolve_address`, `gandon_list_functions`,
`gandon_disasm`, `gandon_listing`, `gandon_decompile`,
`gandon_decompile_to_file`, `gandon_xrefs`, `gandon_strings`,
`gandon_imports`, `gandon_exports`, `gandon_resources`, `gandon_segments`,
`gandon_hex`, `gandon_search_bytes`, `gandon_search_text`,
`gandon_auto_analysis`, `gandon_analysis_status`, `gandon_analysis_wait`,
`gandon_rename`, `gandon_add_comment`, `gandon_patch_bytes`,
`gandon_navigate`, `gandon_save_database`, `gandon_load_database`.

Three of these are worth calling out:

- **`gandon_list_functions`** takes `offset`/`limit` and returns `total` and
  `truncated` - page through a binary with thousands of functions instead of
  getting them all back (or silently only the first 200) in one response.
- **`gandon_decompile_to_file`** decompiles a range of functions straight to
  a file on disk (the plugin writes it directly - it's in-process, no host
  round-trip needed) instead of returning them over the wire. Use this
  rather than looping `gandon_decompile` over hundreds of functions.
- **`gandon_auto_analysis`** with `{"async": true}` starts analysis on its
  own background thread and returns immediately instead of blocking the
  request (and, since the server handles one connection at a time, every
  other client) until a multi-minute scan finishes. Poll with
  `gandon_analysis_status` (non-blocking) or `gandon_analysis_wait`
  (blocks up to `timeout_seconds`, default 30) - the same
  status/wait shape as ida-multi-mcp's `analysis_status`/`analysis_wait`.
- **`gandon_save_database`** / **`gandon_load_database`** read/write the
  same `.gnd` format as File > Save/Load Database, so a session's renames,
  comments, patches, bookmarks and graph layout survive closing
  `gandon_gui.exe` - checkpoint before closing, or let a long-running agent
  resume where it left off. `gandon_load_database` only accepts the native
  `GANDON-GND-*` format, not the legacy Python JSON one (that path can pop a
  blocking dialog if no binary is open, which has no one to click it in
  headless use).

`GET /health` - liveness check, no auth, includes `requests_served`.

## How it's built (for reference)

- `include/gandon/plugin_api.h` (v3): extends the existing native-plugin ABI
  (`GandonPluginHost`) with text-returning calls (`listing_at`,
  `decompile_at`, `strings`, `search_bytes`, ... `patch_bytes`, `rename`,
  added in v2) plus `save_database`/`load_database`/`last_database_error`
  (v3, project persistence). Every v2/v3 call is safe to make from any
  thread. Pagination (`gandon_list_functions`) and `gandon_decompile_to_file`
  needed no ABI change at all - they're built entirely out of the existing
  index-based `function_count`/`function_at`/`decompile_at` calls plus the
  plugin's own file I/O, since the plugin is an in-process DLL. Likewise
  async auto-analysis needed no host change - the plugin just calls the
  existing (blocking) `run_auto_analysis` from its own background thread
  instead of a request-handling one.
- `src/gui_main.cpp`: implements those v2 callbacks. Each one builds a
  `std::function<void()>` job and runs it on the UI thread via
  `SendMessageW(..., WM_RUN_ON_UI, ...)` (blocking, so no extra
  synchronization is needed) before touching `g_database` or any other
  UI-thread-owned state - a plugin's own background thread never touches
  the database directly.
- `plugins/mcp_plugin.cpp`: the plugin DLL. A tiny hand-rolled JSON
  parser/writer and a single-threaded blocking HTTP server (winsock2, one
  request per connection) implement the MCP Streamable HTTP transport and
  dispatch each tool call to the v2 host callbacks above.

### A bug this fixed along the way

`load_native_plugins()` used to build the `GandonPluginHost` struct as a
plain local variable and hand `&api` to every plugin's `GandonPluginInit`.
That struct was destroyed the moment `load_native_plugins()` returned,
so every native plugin (including the bundled example) kept a **dangling**
host pointer afterward - it happened to look like it worked for calls made
very soon after loading, then silently returned garbage. It's now a
function-local `static`, so the pointer stays valid for the process's
lifetime. This fix shipped in the same build as this plugin.
