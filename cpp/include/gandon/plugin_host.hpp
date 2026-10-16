#pragma once

#include "gandon/plugin_api.h"

#include <filesystem>
#include <memory>
#include <string>

namespace gandon {

class PluginHost {
public:
    PluginHost();
    ~PluginHost();
    PluginHost(const PluginHost&) = delete;
    PluginHost& operator=(const PluginHost&) = delete;

    bool load_directory(const std::filesystem::path& directory,
                        const GandonPluginHost& api,
                        std::string& error);
    void unload_all() noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace gandon
