// src/payload/script_runner.cpp
#include "script_runner.hpp"
#include "patterns.hpp"
#include <windows.h>
#include <string>

namespace rex {

static uintptr_t get_module_size(HMODULE mod) {
    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(mod);
    auto nt  = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<BYTE*>(mod) + dos->e_lfanew);
    return nt->OptionalHeader.SizeOfImage;
}

bool ScriptRunner::attach() {
    HMODULE base = GetModuleHandleW(L"RobloxPlayerBeta.exe");
    if (!base) return false;
    uintptr_t start = reinterpret_cast<uintptr_t>(base);
    size_t    size  = get_module_size(base);

    for (const auto& p : kPatterns) {
        auto addr = find_pattern(start, size, p);
        if (!addr) continue;
        if (p.name == "ScriptContext")  script_context_  = *addr;
        if (p.name == "TaskScheduler")  task_scheduler_  = *addr;
    }

    // Resolve internal load / schedule functions the same way.
    // Real code stores the function pointers once patterns hit.

    attached_ = script_context_ != 0;
    return attached_;
}

std::string ScriptRunner::execute(const std::string& source) {
    if (!attached_) return "not attached";
    // Real path:
    // 1. obtain Luau state from ScriptContext
    // 2. set identity
    // 3. compile or load source
    // 4. schedule on TaskScheduler
    // 5. capture print/error via hooked functions or return buffer
    return "[rex] executed " + std::to_string(source.size()) + " bytes (bind your real load here)";
}

std::string ScriptRunner::execute_bytecode(const uint8_t*, size_t) {
    return "bytecode path not wired";
}

void ScriptRunner::set_identity(int) {
    // write the identity level into the correct structure
}

} // namespace rex
