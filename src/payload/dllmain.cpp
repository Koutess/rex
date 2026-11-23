// src/payload/dllmain.cpp
// C++20 | Windows 11 | MSVC | Roblox payload
#include <windows.h>
#include <thread>
#include <string>
#include "../common/pipe.hpp"
#include "script_runner.hpp"
#include "evasion.hpp"

static std::thread g_thread;
static bool g_running = true;

// Simple log so we can see whether the payload is alive
static void log(const char* msg) {
    // writes next to the Roblox exe – easy to check
    char path[MAX_PATH]{};
    GetModuleFileNameA(nullptr, path, MAX_PATH);
    std::string logpath = path;
    auto pos = logpath.find_last_of("\\/");
    if (pos != std::string::npos) logpath = logpath.substr(0, pos + 1);
    logpath += "rex_payload.log";

    HANDLE h = CreateFileA(logpath.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ,
                           nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD w;
        WriteFile(h, msg, (DWORD)strlen(msg), &w, nullptr);
        WriteFile(h, "\r\n", 2, &w, nullptr);
        CloseHandle(h);
    }
}

static void server_main() {
    log("server_main entered");

    rex::evasion::delayed_init([] {
        log("delayed_init fired");

        rex::PipeServer server;
        if (!server.create()) {
            log("CreateNamedPipe failed");
            return;
        }
        log("pipe created, waiting for client");

        if (!server.wait_client()) {
            log("wait_client failed");
            return;
        }
        log("client connected");

        rex::ScriptRunner runner;
        runner.attach();
        log(runner.is_attached() ? "ScriptRunner attached" : "ScriptRunner attach failed");

        while (g_running) {
            auto pkt = server.read_packet();
            if (!pkt) {
                log("read_packet failed / client disconnected");
                break;
            }

            switch (pkt->first) {
            case rex::Cmd::Ping:
                server.write_packet(rex::Cmd::Status, "pong", 4);
                break;
            case rex::Cmd::Execute: {
                std::string src(pkt->second.begin(), pkt->second.end());
                auto result = runner.execute(src);
                server.write_packet(rex::Cmd::Status, result.data(),
                                   static_cast<uint32_t>(result.size()));
                break;
            }
            case rex::Cmd::IsAttached: {
                const char* msg = runner.is_attached() ? "1" : "0";
                server.write_packet(rex::Cmd::Status, msg, 1);
                break;
            }
            case rex::Cmd::SetIdentity:
                if (pkt->second.size() >= 4) {
                    int level = *reinterpret_cast<int*>(pkt->second.data());
                    runner.set_identity(level);
                }
                break;
            case rex::Cmd::Unload:
            case rex::Cmd::Shutdown:
                g_running = false;
                break;
            default:
                break;
            }
        }
        log("server loop exited");
    });
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);

        // Do the least possible work here
        rex::evasion::wipe_headers(hModule);
        // unlink later if you want – it can be fragile right at attach

        g_thread = std::thread(server_main);
        g_thread.detach();
    }
    else if (reason == DLL_PROCESS_DETACH) {
        g_running = false;
    }
    return TRUE;
}
