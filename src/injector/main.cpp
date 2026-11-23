// src/injector/main.cpp
// C++20 | Windows 11 | MSVC | Roblox executor front-end
#include "process.hpp"
#include "manual_map.hpp"
#include "../common/pipe.hpp"

#include <windows.h>
#include <string>
#include <thread>
#include <atomic>
#include <filesystem>
#include <chrono>

namespace fs = std::filesystem;

std::atomic<bool>   g_attached{false};
rex::PipeClient*    g_client = nullptr;
std::string         g_output;
std::string         g_script = R"(print("rex online"))";

int run_ui();

int WINAPI wWinMain(HINSTANCE, HINSTANCE, LPWSTR, int) {
    auto pid = rex::find_roblox();
    if (!pid) {
        MessageBoxW(nullptr, L"RobloxPlayerBeta.exe not found", L"rex", MB_ICONERROR);
        return 1;
    }

    wchar_t path[MAX_PATH]{};
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    fs::path dll_path = fs::path(path).parent_path() / L"payload.dll";

    auto image = rex::read_file(dll_path.wstring());
    if (image.empty()) {
        MessageBoxW(nullptr, L"payload.dll missing", L"rex", MB_ICONERROR);
        return 1;
    }

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, *pid);
    if (!hProc) {
        MessageBoxW(nullptr, L"OpenProcess failed", L"rex", MB_ICONERROR);
        return 1;
    }

    // New signature: pass pid for thread hijacking
    auto map = rex::manual_map(hProc, *pid, image);
    CloseHandle(hProc);

    if (!map.success) {
        MessageBoxW(nullptr,
                    L"manual map / thread hijack failed",
                    L"rex", MB_ICONERROR);
        return 1;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(3000));

    static rex::PipeClient client;
    if (!client.connect(rex::PIPE_NAME, 15000)) {
        MessageBoxW(nullptr,
                    L"pipe connect failed – check rex_payload.log next to Roblox",
                    L"rex", MB_ICONERROR);
        return 1;
    }

    g_client   = &client;
    g_attached = true;

    std::thread([] {
        while (g_attached && g_client) {
            auto pkt = g_client->read_packet();
            if (!pkt) {
                g_attached = false;
                break;
            }
            if (pkt->first == rex::Cmd::Status || pkt->first == rex::Cmd::Execute) {
                g_output.assign(pkt->second.begin(), pkt->second.end());
            }
        }
        g_attached = false;
    }).detach();

    return run_ui();
}
