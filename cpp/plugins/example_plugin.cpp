#include "gandon/plugin_api.h"

#include <cstdio>

static const GandonPluginHost* g_host = nullptr;

static void show_status(void*) {
    if (!g_host || !g_host->status) return;
    char message[256]{};
    const auto functions = g_host->function_count ? g_host->function_count(g_host->user_data) : 0;
    const auto xrefs = g_host->xref_count ? g_host->xref_count(g_host->user_data) : 0;
    uint64_t first_instruction = 0;
    if (functions && g_host->function_instruction_at) {
        GandonInstructionView instruction{};
        if (g_host->function_instruction_at(g_host->user_data, 0, 0, &instruction)) first_instruction = instruction.address;
    }
    std::snprintf(message, sizeof(message), "Native plugin: functions=%llu, xrefs=%llu, first_instruction=0x%llX, current=0x%llX",
        static_cast<unsigned long long>(functions), static_cast<unsigned long long>(xrefs),
        static_cast<unsigned long long>(first_instruction),
        static_cast<unsigned long long>(g_host->current_address ? g_host->current_address(g_host->user_data) : 0));
    g_host->status(g_host->user_data, message);
}

extern "C" GANDON_PLUGIN_EXPORT int GandonPluginInit(
    const GandonPluginHost* host, GandonPluginInfo* info) {
    if (!host || !info || host->api_version != GANDON_PLUGIN_API_VERSION) return 0;
    g_host = host;
    info->api_version = GANDON_PLUGIN_API_VERSION;
    info->name = "Example Native Plugin";
    info->version = "1.0";
    if (host->register_action) {
        host->register_action(host->user_data, "Plugins", "Example Status", show_status, nullptr);
    }
    return 1;
}

extern "C" GANDON_PLUGIN_EXPORT void GandonPluginShutdown() {
    g_host = nullptr;
}
