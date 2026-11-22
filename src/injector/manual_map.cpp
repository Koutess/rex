// src/injector/manual_map.cpp
#include "manual_map.hpp"
#include <winnt.h>

namespace rex {

using f_LoadLibraryA   = HINSTANCE(WINAPI*)(const char*);
using f_GetProcAddress = FARPROC(WINAPI*)(HMODULE, const char*);
using f_DllMain        = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);

struct ManualMapData {
    f_LoadLibraryA   pLoadLibraryA;
    f_GetProcAddress pGetProcAddress;
    BYTE*            pBase;
    HINSTANCE        hModule;
};

// This shellcode runs in the target and finishes the map.
#pragma runtime_checks("", off)
#pragma optimize("", off)
static DWORD WINAPI remote_stub(ManualMapData* pData) {
    if (!pData) return 1;
    BYTE* pBase = pData->pBase;
    auto* pOpt  = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>(pBase)->e_lfanew)->OptionalHeader;

    auto _LoadLibraryA   = pData->pLoadLibraryA;
    auto _GetProcAddress = pData->pGetProcAddress;

    // Relocations
    BYTE* delta = pBase - pOpt->ImageBase;
    if (delta) {
        if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
            auto* pReloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
            while (pReloc->VirtualAddress) {
                UINT count = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* pRelative = reinterpret_cast<WORD*>(pReloc + 1);
                for (UINT i = 0; i < count; ++i, ++pRelative) {
                    if (pRelative[0] >> 12 == IMAGE_REL_BASED_DIR64) {
                        *reinterpret_cast<UINT_PTR*>(pBase + pReloc->VirtualAddress + (pRelative[0] & 0xFFF)) += reinterpret_cast<UINT_PTR>(delta);
                    }
                }
                pReloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pReloc) + pReloc->SizeOfBlock);
            }
        }
    }

    // Imports
    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        auto* pImport = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        while (pImport->Name) {
            char* szMod = reinterpret_cast<char*>(pBase + pImport->Name);
            HINSTANCE hDll = _LoadLibraryA(szMod);
            ULONG_PTR* pThunk = reinterpret_cast<ULONG_PTR*>(pBase + pImport->OriginalFirstThunk);
            ULONG_PTR* pFunc  = reinterpret_cast<ULONG_PTR*>(pBase + pImport->FirstThunk);
            if (!pImport->OriginalFirstThunk) pThunk = pFunc;
            for (; *pThunk; ++pThunk, ++pFunc) {
                if (IMAGE_SNAP_BY_ORDINAL(*pThunk)) {
                    *pFunc = reinterpret_cast<ULONG_PTR>(_GetProcAddress(hDll, reinterpret_cast<char*>(*pThunk & 0xFFFF)));
                } else {
                    auto* pImportByName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + *pThunk);
                    *pFunc = reinterpret_cast<ULONG_PTR>(_GetProcAddress(hDll, pImportByName->Name));
                }
            }
            ++pImport;
        }
    }

    // TLS
    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
        auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
        for (; pCallback && *pCallback; ++pCallback)
            (*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
    }

    // DllMain
    auto DllMain = reinterpret_cast<f_DllMain>(pBase + pOpt->AddressOfEntryPoint);
    DllMain(reinterpret_cast<HINSTANCE>(pBase), DLL_PROCESS_ATTACH, nullptr);

    pData->hModule = reinterpret_cast<HINSTANCE>(pBase);
    return 0;
}
#pragma optimize("", on)
#pragma runtime_checks("", restore)

// Size of the stub we need to copy
static constexpr size_t STUB_SIZE = 0x1000; // safe upper bound

ManualMapResult manual_map(HANDLE hProcess, const std::vector<uint8_t>& image) {
    ManualMapResult res{};
    if (image.size() < sizeof(IMAGE_DOS_HEADER)) return res;

    auto* pDos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.data());
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return res;
    auto* pNt = reinterpret_cast<const IMAGE_NT_HEADERS*>(image.data() + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return res;

    SIZE_T image_size = pNt->OptionalHeader.SizeOfImage;
    BYTE* remote_base = static_cast<BYTE*>(VirtualAllocEx(hProcess, nullptr, image_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!remote_base) return res;

    // Write headers
    if (!WriteProcessMemory(hProcess, remote_base, image.data(), pNt->OptionalHeader.SizeOfHeaders, nullptr)) {
        VirtualFreeEx(hProcess, remote_base, 0, MEM_RELEASE);
        return res;
    }

    // Write sections
    auto* pSection = IMAGE_FIRST_SECTION(pNt);
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; ++i, ++pSection) {
        if (pSection->SizeOfRawData) {
            if (!WriteProcessMemory(hProcess, remote_base + pSection->VirtualAddress,
                image.data() + pSection->PointerToRawData, pSection->SizeOfRawData, nullptr)) {
                VirtualFreeEx(hProcess, remote_base, 0, MEM_RELEASE);
                return res;
            }
        }
    }

    // Allocate + write the mapping data + stub
    ManualMapData data{};
    data.pLoadLibraryA   = LoadLibraryA;
    data.pGetProcAddress = GetProcAddress;
    data.pBase           = remote_base;

    void* remote_data = VirtualAllocEx(hProcess, nullptr, sizeof(data) + STUB_SIZE,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote_data) {
        VirtualFreeEx(hProcess, remote_base, 0, MEM_RELEASE);
        return res;
    }

    WriteProcessMemory(hProcess, remote_data, &data, sizeof(data), nullptr);
    WriteProcessMemory(hProcess, static_cast<BYTE*>(remote_data) + sizeof(data),
        reinterpret_cast<void*>(remote_stub), STUB_SIZE, nullptr);

    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(static_cast<BYTE*>(remote_data) + sizeof(data)),
        remote_data, 0, nullptr);
    if (!hThread) {
        VirtualFreeEx(hProcess, remote_base, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, remote_data, 0, MEM_RELEASE);
        return res;
    }

    WaitForSingleObject(hThread, 15000);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remote_data, 0, MEM_RELEASE); // stub no longer needed

    res.success     = true;
    res.remote_base = reinterpret_cast<uintptr_t>(remote_base);
    return res;
}

} // namespace rex
