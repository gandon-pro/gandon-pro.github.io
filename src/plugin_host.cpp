#include "gandon/plugin_host.hpp"

#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

namespace gandon {

struct PluginHost::Impl {
    struct LoadedPlugin {
#ifdef _WIN32
        HMODULE module{nullptr};
#endif
        GandonPluginShutdownFn shutdown{nullptr};
        std::string name;
    };
    std::vector<LoadedPlugin> plugins;
};

PluginHost::PluginHost() : impl_(std::make_unique<Impl>()) {}
PluginHost::~PluginHost() { unload_all(); }

bool PluginHost::load_directory(const std::filesystem::path& directory,
                                const GandonPluginHost& api,
                                std::string& error) {
#ifdef _WIN32
    if (!std::filesystem::exists(directory)) return true;
    for (const auto& entry : std::filesystem::directory_iterator(directory)) {
        if (entry.path().extension() != ".dll") continue;
        HMODULE module = LoadLibraryW(entry.path().c_str());
        if (!module) continue;
        // These are the exported C symbols; GandonPluginInitFn is a typedef.
        auto init = reinterpret_cast<GandonPluginInitFn>(GetProcAddress(module, "GandonPluginInit"));
        if (!init) { FreeLibrary(module); continue; }
        GandonPluginInfo info{GANDON_PLUGIN_API_VERSION, nullptr, nullptr};
        if (!init(&api, &info) || info.api_version != GANDON_PLUGIN_API_VERSION) {
            FreeLibrary(module);
            continue;
        }
        auto shutdown = reinterpret_cast<GandonPluginShutdownFn>(GetProcAddress(module, "GandonPluginShutdown"));
        impl_->plugins.push_back({module, shutdown, info.name ? info.name : entry.path().stem().string()});
    }
    return true;
#else
    (void)directory; (void)api;
    error = "Native plugin loading is currently implemented for Windows.";
    return false;
#endif
}

void PluginHost::unload_all() noexcept {
    if (!impl_) return;
    for (auto it = impl_->plugins.rbegin(); it != impl_->plugins.rend(); ++it) {
        if (it->shutdown) it->shutdown();
#ifdef _WIN32
        if (it->module) FreeLibrary(it->module);
#endif
    }
    impl_->plugins.clear();
}

} // namespace gandon

