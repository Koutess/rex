// src/payload/payload.cpp
// C++20 | Windows 11 | MSVC | Injected Payload
#include "../common/pipe.hpp"
#include "../common/protocol.hpp"
#include <windows.h>

struct PayloadContext {
    HMODULE hModule;
};

static DWORD WINAPI PayloadThread(LPVOID lpParam) {
    auto* ctx = static_cast<PayloadContext*>(lpParam);
    if (!ctx) return 1;

    rex::PipeServer server;
    if (!server.create(rex::PIPE_NAME)) {
        delete ctx;
        return 1;
    }

    if (!server.wait_client()) {
        delete ctx;
        return 1;
    }

    while (true) {
        auto pkt = server.read_packet();
        if (!pkt) break;

        auto [cmd, data] = *pkt;

        switch (cmd) {
            case rex::Cmd::Ping: {
                const char* pong = "Pong";
                server.write_packet(rex::Cmd::Status, pong, strlen(pong));
                break;
            }
            case rex::Cmd::Execute: {
                // In a real executor, you would call luaL_loadbuffer here.
                const char* msg = "Script executed (stub)";
                server.write_packet(rex::Cmd::Status, msg, strlen(msg));
                break;
            }
            case rex::Cmd::Unload: {
                server.disconnect();
                FreeLibraryAndExitThread(ctx->hModule, 0);
                return 0;
            }
            default:
                break;
        }
    }
    
    delete ctx;
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_calling, LPVOID lpReserved) {
    if (ul_reason_for_calling == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        
        auto* ctx = new PayloadContext{ hModule };
        HANDLE hThread = CreateThread(nullptr, 0, PayloadThread, ctx, 0, nullptr);
        if (hThread) CloseHandle(hThread);
    }
    return TRUE;
}
