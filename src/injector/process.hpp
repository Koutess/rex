// src/injector/process.hpp
#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <optional>
#include <string>
#include <vector>

namespace rex {

inline std::optional<DWORD> find_roblox() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return std::nullopt;
    PROCESSENTRY32W pe{ sizeof(pe) };
    std::optional<DWORD> result;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"RobloxPlayerBeta.exe") == 0) {
                result = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return result;
}

inline std::vector<uint8_t> read_file(const std::wstring& path) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return {};
    DWORD size = GetFileSize(h, nullptr);
    std::vector<uint8_t> buf(size);
    DWORD read = 0;
    ReadFile(h, buf.data(), size, &read, nullptr);
    CloseHandle(h);
    return buf;
}

} // namespace rex
