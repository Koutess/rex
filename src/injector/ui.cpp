// src/injector/ui.cpp
// Minimal external ImGui window. Full source in real project; this is the control surface.
#include <imgui.h>
#include <imgui_impl_win32.h>
#include <imgui_impl_dx11.h>
#include <d3d11.h>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include "../common/pipe.hpp"

// … standard ImGui + D3D11 boilerplate (create device, window, message loop) …

// Global state shared with main
extern std::atomic<bool> g_attached;
extern rex::PipeClient*  g_client;
extern std::string       g_output;
extern std::string       g_script;

void render_ui() {
    ImGui::Begin("rex");
    if (ImGui::Button(g_attached ? "Detach" : "Attach")) {
        // signal main thread
    }
    ImGui::SameLine();
    if (ImGui::Button("Execute") && g_client && g_attached) {
        g_client->write_packet(rex::Cmd::Execute, g_script.data(), static_cast<uint32_t>(g_script.size()));
    }
    ImGui::InputTextMultiline("##script", &g_script, ImVec2(-1, 300));
    ImGui::BeginChild("output", ImVec2(-1, 150), true);
    ImGui::TextUnformatted(g_output.c_str());
    ImGui::EndChild();
    ImGui::End();
}
