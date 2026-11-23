// src/injector/manual_map.hpp
#pragma once
#include <windows.h>
#include <vector>
#include <cstdint>

namespace rex {

struct ManualMapResult {
    bool     success     = false;
    uintptr_t remote_base = 0;
};

// Manual map using thread hijacking (no CreateRemoteThread)
ManualMapResult manual_map(HANDLE hProcess, DWORD pid, const std::vector<uint8_t>& dll_image);

} // namespace rex
