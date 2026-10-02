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

#define GANDON_PLUGIN_API_VERSION 1u

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

