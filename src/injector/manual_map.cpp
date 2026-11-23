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
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return tid;
}

// -------------------- Public API --------------------
ManualMapResult manual_map(HANDLE hProcess, DWORD pid, const std::vector<uint8_t>& image) {
    ManualMapResult res{};
    if (image.size() < sizeof(IMAGE_DOS_HEADER)) return res;
    
    auto* pDos = (const IMAGE_DOS_HEADER*)image.data();
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return res;
    
    auto* pNt = (const IMAGE_NT_HEADERS*)(image.data() + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return res;
    
    SIZE_T image_size = pNt->OptionalHeader.SizeOfImage;
    BYTE* remote_base = (BYTE*)VirtualAllocEx(hProcess, nullptr, image_size,
                                              MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote_base) return res;
    
    // Write headers + sections
    if (!WriteProcessMemory(hProcess, remote_base, image.data(),
                            pNt->OptionalHeader.SizeOfHeaders, nullptr)) {
        VirtualFreeEx(hProcess, remote_base, 0, MEM_RELEASE);
        return res;
    }
    
    auto* pSec = IMAGE_FIRST_SECTION(const_cast<IMAGE_NT_HEADERS*>(pNt));
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; ++i, ++pSec) {
        if (pSec->SizeOfRawData == 0) continue;
        if (!WriteProcessMemory(hProcess, remote_base + pSec->VirtualAddress,
                                image.data() + pSec->PointerToRawData,
                                pSec->SizeOfRawData, nullptr)) {
            VirtualFreeEx(hProcess, remote_base, 0, MEM_RELEASE);
            return res;
        }
    }
    
    // Prepare mapping data + stub
    ManualMapData data{};
    data.pLoadLibraryA   = LoadLibraryA;
    data.pGetProcAddress = GetProcAddress;
    data.pBase           = remote_base;
    data.status          = 0xFFFFFFFF;
    
    SIZE_T total = sizeof(data) + STUB_SIZE;
    void* remote_data = VirtualAllocEx(hProcess, nullptr, total,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote_data) {
        VirtualFreeEx(hProcess, remote_base, 0, MEM_RELEASE);
        return res;
    }
    
    WriteProcessMemory(hProcess, remote_data, &data, sizeof(data), nullptr);
    WriteProcessMemory(hProcess, (BYTE*)remote_data + sizeof(data),
                       (const void*)&remote_stub, STUB_SIZE, nullptr);
    
    // ----- Thread hijack -----
    DWORD tid = find_hijackable_thread(pid);
    if (!tid) {
        VirtualFreeEx(hProcess, remote_base, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, remote_data, 0, MEM_RELEASE);
        return res;
    }
    
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
    if (!hThread) {
        VirtualFreeEx(hProcess, remote_base, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, remote_data, 0, MEM_RELEASE);
        return res;
    }
    
    SuspendThread(hThread);
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &ctx)) {
        ResumeThread(hThread);
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, remote_base, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, remote_data, 0, MEM_RELEASE);
        return res;
    }
    
    // Save original RIP so we can return later if desired
    ctx.Rip = (DWORD64)((BYTE*)remote_data + sizeof(data));
    ctx.Rcx = (DWORD64)remote_data;          // first argument (x64 calling convention)
    // Align stack to 16 bytes
    ctx.Rsp = (ctx.Rsp - 0x100) & ~0xF;      
    
    if (!SetThreadContext(hThread, &ctx)) {
        ResumeThread(hThread);
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, remote_base, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, remote_data, 0, MEM_RELEASE);
        return res;
    }
    
    ResumeThread(hThread);
    CloseHandle(hThread);
    
    // Give the stub time to finish
    Sleep(2000);
    
    // Read status back
    ManualMapData result{};
    ReadProcessMemory(hProcess, remote_data, &result, sizeof(result), nullptr);
    
    VirtualFreeEx(hProcess, remote_data, 0, MEM_RELEASE);
    
    if (result.status != 0) {
        VirtualFreeEx(hProcess, remote_base, 0, MEM_RELEASE);
        return res;
    }
    
    res.success     = true;
    res.remote_base = (uintptr_t)remote_base;
    return res;
}
} // namespace rex
