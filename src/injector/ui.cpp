// src/injector/ui.cpp
// C++20 | Windows 11 | MSVC | ImGui front-end
#include <imgui.h>
#include <imgui_impl_win32.h>
#include <imgui_impl_dx11.h>
#include <d3d11.h>
#include <tchar.h>
#include <string>
#include <atomic>

// Shared with main.cpp
extern std::atomic<bool> g_attached;
extern class rex::PipeClient* g_client;   // forward ok if you keep the include order
extern std::string g_output;
extern std::string g_script;

// Forward declare the packet writer (or include the header)
namespace rex {
    enum class Cmd : uint32_t;
    class PipeClient {
    public:
        bool write_packet(Cmd cmd, const void* data = nullptr, uint32_t size = 0);
    };
    // Minimal re-declare so we don't pull the whole header if you prefer
}

// Data
static ID3D11Device*            g_pd3dDevice = nullptr;
static ID3D11DeviceContext*     g_pd3dDeviceContext = nullptr;
static IDXGISwapChain*          g_pSwapChain = nullptr;
static ID3D11RenderTargetView*  g_mainRenderTargetView = nullptr;
static HWND                     g_hWnd = nullptr;

// Forward
bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void CreateRenderTarget();
void CleanupRenderTarget();
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// Simple fixed buffer for the multiline editor
static char g_script_buf[1024 * 64] = "print(\"rex online\")";

int run_ui() {
    // Copy initial script into the buffer once
    if (!g_script.empty()) {
        strncpy_s(g_script_buf, g_script.c_str(), sizeof(g_script_buf) - 1);
    }

    WNDCLASSEXW wc = { sizeof(wc), CS_CLASSDC, WndProc, 0L, 0L,
                       GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr,
                       L"rex", nullptr };
    RegisterClassExW(&wc);
    g_hWnd = CreateWindowW(wc.lpszClassName, L"rex", WS_OVERLAPPEDWINDOW,
                           100, 100, 720, 640, nullptr, nullptr, wc.hInstance, nullptr);

    if (!CreateDeviceD3D(g_hWnd)) {
        CleanupDeviceD3D();
        UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    ShowWindow(g_hWnd, SW_SHOWDEFAULT);
    UpdateWindow(g_hWnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    ImGui::StyleColorsDark();
    ImGui_ImplWin32_Init(g_hWnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    bool done = false;
    while (!done) {
        MSG msg;
        while (PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            if (msg.message == WM_QUIT)
                done = true;
        }
        if (done) break;

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        // ---- UI ----
        ImGui::SetNextWindowSize(ImVec2(680, 580), ImGuiCond_FirstUseEver);
        ImGui::Begin("rex");

        if (ImGui::Button(g_attached ? "Detach" : "Attach")) {
            // main.cpp owns the actual attach logic; this is just a visual for now
        }
        ImGui::SameLine();
        if (ImGui::Button("Execute") && g_client && g_attached) {
            g_script = g_script_buf; // sync back
            g_client->write_packet(rex::Cmd::Execute,
                                   g_script.data(),
                                   static_cast<uint32_t>(g_script.size()));
        }

        ImGui::Separator();
        ImGui::Text("Script");
        ImGui::InputTextMultiline("##script",
                                  g_script_buf,
                                  sizeof(g_script_buf),
                                  ImVec2(-1, 300));

        ImGui::Text("Output");
        ImGui::BeginChild("output", ImVec2(-1, 150), true);
        ImGui::TextUnformatted(g_output.c_str());
        ImGui::EndChild();

        ImGui::End();
        // ---- end UI ----

        ImGui::Render();
        const float clear[4] = { 0.08f, 0.08f, 0.10f, 1.0f };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        g_pSwapChain->Present(1, 0);
    }

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    CleanupDeviceD3D();
    DestroyWindow(g_hWnd);
    UnregisterClassW(wc.lpszClassName, wc.hInstance);
    return 0;
}

// ---------- D3D11 helpers ----------
bool CreateDeviceD3D(HWND hWnd) {
    DXGI_SWAP_CHAIN_DESC sd{};
    sd.BufferCount = 2;
    sd.BufferDesc.Width = 0;
    sd.BufferDesc.Height = 0;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.SampleDesc.Quality = 0;
    sd.Windowed = TRUE;
    sd.SwapEffect = 
