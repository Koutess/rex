// src/payload/patterns.cpp
// C++20 | Windows 11 | MSVC
#include "patterns.hpp"
#include <vector>
#include <sstream>
#include <cctype>

namespace rex {

static std::vector<int> parse_pattern(std::string_view sig) {
    std::vector<int> bytes;
    std::string token;
    std::istringstream iss{std::string(sig)};
    while (iss >> token) {
        if (token == "?" || token == "??") {
            bytes.push_back(-1);
        } else {
            bytes.push_back(static_cast<int>(std::stoul(token, nullptr, 16)));
        }
    }
    return bytes;
}

std::optional<uintptr_t> find_pattern(uintptr_t module_base, size_t module_size, const Pattern& p) {
    auto pattern = parse_pattern(p.bytes);
    if (pattern.empty() || module_size < pattern.size())
        return std::nullopt;

    const auto* start = reinterpret_cast<const uint8_t*>(module_base);
    const size_t limit = module_size - pattern.size();

    for (size_t i = 0; i <= limit; ++i) {
        bool match = true;
        for (size_t j = 0; j < pattern.size(); ++j) {
            if (pattern[j] != -1 && start[i + j] != static_cast<uint8_t>(pattern[j])) {
                match = false;
                break;
            }
        }
        if (!match) continue;

        uintptr_t addr = module_base + i;
        if (p.relative) {
            // typical RIP-relative: addr + offset + size + *(int32_t*)(addr + offset)
            int32_t rel = *reinterpret_cast<const int32_t*>(addr + p.relative_offset);
            addr = addr + p.relative_offset + p.relative_size + rel;
        }
        return addr;
    }
    return std::nullopt;
}

} // namespace rex
