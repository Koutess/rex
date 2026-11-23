// src/payload/payload.cpp
// C++20 | Windows 11 | MSVC | Injected Payload
#include "../common/pipe.hpp"
#include "../common/protocol.hpp"
#include <windows.h>
#include <thread>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_calling, LPVOID lpReserved) {
    if (ul_reason_for_calling == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        
        CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
            rex::PipeServer server;
            if (!server.create(rex::PIPE_NAME)) {
                return 1;
            }
            
            if (!server.wait_client()) {
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
                        const char* msg = "Script executed (stub)";
                        server.write_packet(rex::Cmd::Status, msg, strlen(msg));
                        break;
                    }
                    case rex::Cmd::Unload: {
                        server.disconnect();
                        FreeLibraryAndExitThread(hModule, 0);
                        return 0;
                    }
                    default:
                        break;
                }
            }
            return 0;
        }, nullptr, 0, nullptr);
    }
    return TRUE;
}
