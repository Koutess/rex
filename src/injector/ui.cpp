// src/injector/ui.cpp
#include <windows.h>
#include <string>

extern std::atomic<bool> g_attached;
extern std::string g_output;
extern std::string g_script;
extern rex::PipeClient* g_client;

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HWND hEdit, hBtn, hStatus;
    
    switch (msg) {
        case WM_CREATE: {
            hEdit = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL,
                                  10, 10, 560, 300, hwnd, nullptr, nullptr, nullptr);
            hBtn = CreateWindowW(L"BUTTON", L"Execute", WS_CHILD | WS_VISIBLE,
                                 10, 320, 100, 30, hwnd, (HMENU)1, nullptr, nullptr);
            hStatus = CreateWindowW(L"STATIC", L"Attached", WS_CHILD | WS_VISIBLE,
                                    120, 320, 100, 30, hwnd, nullptr, nullptr, nullptr);
            break;
        }
        case WM_COMMAND: {
            if (LOWORD(wParam) == 1 && g_client && g_attached) {
                wchar_t buf[4096];
                GetWindowTextW(hEdit, buf, 4096);
                int len = WideCharToMultiByte(CP_UTF8, 0, buf, -1, nullptr, 0, nullptr, nullptr);
                std::string script(len, '\0');
                WideCharToMultiByte(CP_UTF8, 0, buf, -1, script.data(), len, nullptr, nullptr);
                
                g_client->write_packet(rex::Cmd::Execute, script.c_str(), script.size());
            }
            break;
        }
        case WM_DESTROY: {
            PostQuitMessage(0);
            break;
        }
        default:
            return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

int run_ui() {
    WNDCLASSW wc = { sizeof(wc) };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.lpszClassName = L"RexUI";
    RegisterClassW(&wc);

    HWND hwnd = CreateWindowExW(0, L"RexUI", L"rex executor", WS_OVERLAPPEDWINDOW,
                                CW_USEDEFAULT, CW_USEDEFAULT, 600, 400, nullptr, nullptr, nullptr, nullptr);
    ShowWindow(hwnd, SW_SHOW);

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return (int)msg.wParam;
}
