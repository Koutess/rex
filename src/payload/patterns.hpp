// src/payload/patterns.hpp
#pragma once
#include <cstdint>
#include <string_view>
#include <optional>

namespace rex {

struct Pattern {
    std::string_view name;
    std::string_view bytes;   // "48 8B 05 ?? ?? ?? ?? 48 85 C0 74"
    bool relative = false;
    int  relative_offset = 0;
    int  relative_size = 4;
};

// Current patterns must be updated every Roblox deploy.
// Keep a small table keyed by Roblox version hash or just rescan every launch.
inline const Pattern kPatterns[] = {
    { "ScriptContext",   "48 8B 0D ?? ?? ?? ?? 48 85 C9 74 ?? E8", true, 3, 4 },
    { "TaskScheduler",   "48 8B 05 ?? ?? ?? ?? 48 8B 48 08 48 85 C9", true, 3, 4 },
    // add more as you reverse them
};

std::optional<uintptr_t> find_pattern(uintptr_t module_base, size_t module_size, const Pattern& p);

} // namespace rex
