#pragma once

#include <stdint.h>

#ifdef _WIN32
#  define GANDON_PLUGIN_EXPORT __declspec(dllexport)
#else
#  define GANDON_PLUGIN_EXPORT __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define GANDON_PLUGIN_API_VERSION 3u

typedef struct GandonFunctionView {
    uint64_t start;
    const char* name;
} GandonFunctionView;

typedef struct GandonXrefView {
    uint64_t from;
    uint64_t to;
    const char* kind;
} GandonXrefView;

typedef struct GandonInstructionView {
    uint64_t address;
    uint32_t size;
    const char* mnemonic;
    const char* operands;
} GandonInstructionView;

/* Optional analysis/debugger callbacks were appended to preserve the v1 ABI. */
typedef uint64_t (*GandonFunctionCountFn)(void* user_data);
typedef int (*GandonFunctionAtFn)(void* user_data, uint64_t index, GandonFunctionView* out);
typedef uint64_t (*GandonXrefCountFn)(void* user_data);
typedef int (*GandonXrefAtFn)(void* user_data, uint64_t index, GandonXrefView* out);
typedef uint64_t (*GandonFunctionInstructionCountFn)(void* user_data, uint64_t function_index);
typedef int (*GandonFunctionInstructionAtFn)(void* user_data, uint64_t function_index,
                                             uint64_t instruction_index, GandonInstructionView* out);
typedef int (*GandonReadProcessBytesFn)(void* user_data, uint64_t address, uint8_t* out, uint64_t size);

/* v2: text-returning analysis calls, for plugins that need the same live
 * views the GUI shows (listing, decompiler, strings, imports...) rather than
 * re-deriving them from the raw function/xref/instruction enumerations
 * above. Every GandonText* callback returns a UTF-8, NUL-terminated string
 * owned by the host, valid only until the SAME host function is called
 * again on the SAME thread (classic strtok-style buffer reuse) - copy it
 * before making another host call. A null return means "no database is
 * loaded" or "address/name could not be resolved".
 * Every call below is safe to make from any thread: the host marshals the
 * work onto its own UI thread internally and blocks the caller until done,
 * so a plugin never needs its own locking around the live database. */
typedef const char* (*GandonTextFn)(void* user_data);
typedef const char* (*GandonTextAtAddressFn)(void* user_data, uint64_t address);
typedef int (*GandonResolveAddressFn)(void* user_data, const char* text, uint64_t* out_address);
typedef const char* (*GandonDecompileFn)(void* user_data, uint64_t address, int address_comments, int* out_ok);
typedef const char* (*GandonHexDumpFn)(void* user_data, uint64_t address, uint64_t rows);
typedef const char* (*GandonStringsFn)(void* user_data, uint64_t min_length);
typedef const char* (*GandonSearchBytesFn)(void* user_data, const char* hex_pattern_with_question_mark_wildcards);
typedef const char* (*GandonSearchTextFn)(void* user_data, const char* ascii_text);
typedef const char* (*GandonRunAutoAnalysisFn)(void* user_data); /* returns a short summary line */
typedef int (*GandonRenameFn)(void* user_data, uint64_t address, const char* new_name);
typedef int (*GandonAddCommentFn)(void* user_data, uint64_t address, const char* comment_utf8);
/* Patches `size` bytes at `address` in the LIVE, open database (pushes an
 * undo entry the user can revert with Ctrl+Z / Undo Patch, same as any
 * other in-GUI patch) and refreshes the open views. Returns 1 on success. */
typedef int (*GandonPatchBytesFn)(void* user_data, uint64_t address, const uint8_t* bytes, uint64_t size);

/* v3: project persistence, equivalent to File > Save/Load Database (.gnd) in
 * the GUI, exposed so a plugin can checkpoint/restore the live session
 * (renames, comments, patches, bookmarks, graph layout) instead of losing it
 * all when gandon_gui.exe closes. `path` is a UTF-8 filesystem path.
 * load_database ONLY accepts the native GANDON-GND text format (not the
 * legacy Python JSON format, which the GUI's own file picker still supports)
 * so a plugin call never has to deal with a blocking file-format prompt. */
typedef int (*GandonSaveDatabaseFn)(void* user_data, const char* path);
typedef int (*GandonLoadDatabaseFn)(void* user_data, const char* path);
/* Reason the most recent save_database/load_database call returned 0, or ""
 * if it succeeded / none has been made yet. strtok-style buffer like the
 * other GandonTextFn callbacks above. */
typedef GandonTextFn GandonLastDatabaseErrorFn;

typedef struct GandonPluginHost {
    uint32_t api_version;
    void* user_data;
    void (*log)(void* user_data, const char* message);
    void (*status)(void* user_data, const char* message);
    uint64_t (*current_address)(void* user_data);
    int (*read_file_bytes)(void* user_data, uint64_t offset, uint8_t* out, uint64_t size);
    void (*navigate)(void* user_data, uint64_t address);
    int (*register_action)(void* user_data, const char* menu, const char* title,
                           void (*callback)(void* callback_user_data),
                           void* callback_user_data);
    GandonFunctionCountFn function_count;
    GandonFunctionAtFn function_at;
    GandonXrefCountFn xref_count;
    GandonXrefAtFn xref_at;
    GandonFunctionInstructionCountFn function_instruction_count;
    GandonFunctionInstructionAtFn function_instruction_at;
    GandonReadProcessBytesFn read_process_bytes;

    /* v2 (GANDON_PLUGIN_API_VERSION 2). NULL on a v1 host. */
    GandonTextFn info_json;              /* format/arch/base/entry/sections/counts, as JSON */
    GandonResolveAddressFn resolve_address; /* hex/decimal/name/label -> address */
    GandonTextAtAddressFn listing_at;    /* IDA-style text listing of the function at `address` */
    GandonDecompileFn decompile_at;      /* C-like pseudocode (x86/x64 only); *out_ok tells success */
    GandonHexDumpFn hex_dump_at;
    GandonStringsFn strings;
    GandonTextFn imports_text;
    GandonTextFn exports_text;
    GandonTextFn resources_text;
    GandonTextFn segments_text;
    GandonSearchBytesFn search_bytes;    /* space-separated hex, "??" wildcard byte */
    GandonSearchTextFn search_text;
    GandonRunAutoAnalysisFn run_auto_analysis;
    GandonRenameFn rename;
    GandonAddCommentFn add_comment;
    GandonPatchBytesFn patch_bytes;      /* live patch + undo entry, like Edit > Patch Instruction */

    /* v3 (GANDON_PLUGIN_API_VERSION 3). NULL on a v1/v2 host. */
    GandonSaveDatabaseFn save_database;  /* write the live session to a .gnd file, like File > Save Database */
    GandonLoadDatabaseFn load_database;  /* replace the live session from a .gnd file, like File > Load Database */
    GandonLastDatabaseErrorFn last_database_error; /* why the most recent save/load call above returned 0 */
} GandonPluginHost;

typedef struct GandonPluginInfo {
    uint32_t api_version;
    const char* name;
    const char* version;
} GandonPluginInfo;

typedef int (*GandonPluginInitFn)(const GandonPluginHost* host, GandonPluginInfo* info);
typedef void (*GandonPluginShutdownFn)(void);

#ifdef __cplusplus
}
#endif

