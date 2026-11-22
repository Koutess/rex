// src/injector/manual_map.hpp
#pragma once
#include <windows.h>
#include <vector>
#include <cstdint>

namespace rex {

struct ManualMapResult {
    bool success = false;
    uintptr_t remote_base = 0;
};

// Full manual map: allocate, copy sections, relocate, resolve imports, TLS, call DllMain.
// No LoadLibrary. Module never appears in PEB module list if caller also unlinks (done inside payload).
ManualMapResult manual_map(HANDLE hProcess, const std::vector<uint8_t>& dll_image);

} // namespace rex
