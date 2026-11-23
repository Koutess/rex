// src/injector/manual_map.cpp
// C++20 | Windows 11 | MSVC | Manual map + thread hijack
#include "manual_map.hpp"
#include <winnt.h>
#include <tlhelp32.h>
#include <vector>
#include <cstring>

namespace rex {
using f_LoadLibraryA   = HINSTANCE(WINAPI*)(const char*);
using f_GetProcAddress = FARPROC(WINAPI*)(HMODULE, const char*);
using f_DllMain        = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);

struct ManualMapData {
    f_LoadLibraryA   pLoadLibraryA;
    f_GetProcAddress pGetProcAddress;
    BYTE*            pBase;
    HINSTANCE        hModule;
    DWORD            status;          // 0 = success
};

// -------------------- Remote stub (runs inside Roblox) --------------------
#pragma runtime_checks("", off)
#pragma optimize("", off)
static DWORD WINAPI remote_stub(ManualMapData* pData) {
    if (!pData) return 0x1000;
    
    BYTE* pBase = pData->pBase;
    auto* pDos  = reinterpret_cast<IMAGE_DOS_HEADER*>(pBase);
    auto* pNt   = reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + pDos->e_lfanew);
    auto* pOpt  = &pNt->OptionalHeader;
    
    auto _LoadLibraryA   = pData->pLoadLibraryA;
    auto _GetProcAddress = pData->pGetProcAddress;
    
    // Relocations
    ptrdiff_t delta = pBase - reinterpret_cast<BYTE*>(static_cast<uintptr_t>(pOpt->ImageBase));
    if (delta && pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        auto* pReloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
            pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        while (pReloc->VirtualAddress) {
            UINT count = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* pRel = reinterpret_cast<WORD*>(pReloc + 1);
            for (UINT i = 0; i < count; ++i, ++pRel) {
                if ((*pRel >> 12) == IMAGE_REL_BASED_DIR64) {
                    *reinterpret_cast<UINT_PTR*>(pBase + pReloc->VirtualAddress + (*pRel & 0xFFF)) +=
                        static_cast<UINT_PTR>(delta);
                }
            }
            pReloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
                reinterpret_cast<BYTE*>(pReloc) + pReloc->SizeOfBlock);
        }
    }
    
    // Imports
    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        auto* pImport = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
            pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        while (pImport->Name) {
            char* szMod = reinterpret_cast<char*>(pBase + pImport->Name);
            HINSTANCE hDll = _LoadLibraryA(szMod);
            if (!hDll) { pData->status = 0x2000; return 0x2000; }
            
            ULONG_PTR* pThunk = reinterpret_cast<ULONG_PTR*>(pBase + pImport->OriginalFirstThunk);
            ULONG_PTR* pFunc  = reinterpret_cast<ULONG_PTR*>(pBase + pImport->FirstThunk);
            if (!pImport->OriginalFirstThunk) pThunk = pFunc;
            
            for (; *pThunk; ++pThunk, ++pFunc) {
                if (IMAGE_SNAP_BY_ORDINAL(*pThunk)) {
                    *pFunc = (ULONG_PTR)_GetProcAddress(hDll, (const char*)(*pThunk & 0xFFFF));
                } else {
                    auto* pibn = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + *pThunk);
                    *pFunc = (ULONG_PTR)_GetProcAddress(hDll, pibn->Name);
                }
            }
            ++pImport;
        }
    }
    
    // TLS
    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
        auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(
            pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
        for (; pCallback && *pCallback; ++pCallback)
            (*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
    }
    
    // DllMain
    auto entry = reinterpret_cast<f_DllMain>(pBase + pOpt->AddressOfEntryPoint);
    BOOL ok = entry((HINSTANCE)pBase, DLL_PROCESS_ATTACH, nullptr);
    pData->hModule = (HINSTANCE)pBase;
    pData->status  = ok ? 0 : 0x3000;
    return pData->status;
}
#pragma optimize("", on)
#pragma runtime_checks("", restore)

static constexpr size_t STUB_SIZE = 0x2000;

// -------------------- Thread hijack helpers --------------------
static DWORD find_hijackable_thread(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    
    THREADENTRY32 te{ sizeof(te) };
    DWORD tid = 0;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE h = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                if (h) {
                    tid = te.th32ThreadID;
                    CloseHandle(h);
                    break;
                }
            }
        } while (Thread32Next(s
