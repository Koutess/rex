cmake_minimum_required(VERSION 3.25)
project(rex LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

find_package(imgui CONFIG REQUIRED)

add_library(payload SHARED
    src/payload/dllmain.cpp
    src/payload/script_runner.cpp
    src/payload/evasion.cpp
)
target_include_directories(payload PRIVATE src)
target_compile_definitions(payload PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
target_link_libraries(payload PRIVATE)
set_target_properties(payload PROPERTIES OUTPUT_NAME "payload" PREFIX "")

add_executable(rex WIN32
    src/injector/main.cpp
    src/injector/manual_map.cpp
    src/injector/ui.cpp
)
target_include_directories(rex PRIVATE src)
target_compile_definitions(rex PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
target_link_libraries(rex PRIVATE imgui::imgui d3d11 dxgi)
set_target_properties(rex PROPERTIES WIN32_EXECUTABLE TRUE)

add_custom_command(TARGET rex POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_FILE:payload> $<TARGET_FILE_DIR:rex>
)
