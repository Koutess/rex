// src/payload/dllmain.cpp
#include <windows.h>
#include <thread>
#include "../common/pipe.hpp"
#include "script_runner.hpp"
#include "evasion.hpp"

static std::thread g_thread;
static bool g_running = true;

static void server_main() {
    rex::evasion::delayed_init([] {
        rex::PipeServer server;
        if (!server.create()) return;
        if (!server.wait_client()) return;

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
                server.write_packet(rex::Cmd::Status, result.data(), static_cast<uint32_t>(result.size()));
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
    });
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        rex::evasion::wipe_headers(hModule);
        rex::evasion::unlink_module(hModule);
        // rex::evasion::disable_etw(); // enable when ready
        g_thread = std::thread(server_main);
        g_thread.detach();
    } else if (reason == DLL_PROCESS_DETACH) {
        g_running = false;
    }
    return TRUE;
}
