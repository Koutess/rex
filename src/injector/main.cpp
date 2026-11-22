// src/injector/main.cpp
#include "process.hpp"
#include "manual_map.hpp"
#include "../common/pipe.hpp"
#include <windows.h>
#include <string>
#include <thread>
#include <atomic>
#include <filesystem>

namespace fs = std::filesystem;

std::atomic<bool> g_attached{false};
rex::PipeClient*  g_client = nullptr;
std::string       g_output;
std::string       g_script = R"(print("rex online"))";

// Forward declare the ImGui entry (implemented in ui.cpp)
int run_ui();

int WINAPI wWinMain(HINSTANCE, HINSTANCE, LPWSTR, int) {
    auto pid = rex::find_roblox();
    if (!pid) {
        MessageBoxW(nullptr, L"RobloxPlayerBeta.exe not found", L"rex", MB_ICONERROR);
        return 1;
    }

    wchar_t path[MAX_PATH];
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

    auto map = rex::manual_map(hProc, image);
    CloseHandle(hProc);
    if (!map.success) {
        MessageBoxW(nullptr, L"manual map failed", L"rex", MB_ICONERROR);
        return 1;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(1200)); // let payload spin pipe

    static rex::PipeClient client;
    if (!client.connect()) {
        MessageBoxW(nullptr, L"pipe connect failed", L"rex", MB_ICONERROR);
        return 1;
    }
    g_client = &client;
    g_attached = true;

    // Background reader
    std::thread([&] {
        while (g_attached) {
            auto pkt = client.read_packet();
            if (!pkt) break;
            if (pkt->first == rex::Cmd::Status || pkt->first == rex::Cmd::Execute) {
                g_output.assign(pkt->second.begin(), pkt->second.end());
            }
        }
        g_attached = false;
    }).detach();

    return run_ui(); // blocks until window closed
}
