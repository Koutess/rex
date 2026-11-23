cmake_minimum_required(VERSION 3.20)
project(rex_luau_runner LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
set(LUAU_BUILD_CLI OFF CACHE BOOL "" FORCE)
set(LUAU_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(LUAU_BUILD_WEB OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
    luau
    GIT_REPOSITORY https://github.com/luau-lang/luau.git
    GIT_TAG master
    GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(luau)

add_executable(luau_runner
    src/runner/luau_runner.hpp
    src/runner/luau_runner.cpp
    src/runner/main.cpp
)

target_include_directories(luau_runner PRIVATE
    src/runner
    ${luau_SOURCE_DIR}/VM/include
    ${luau_SOURCE_DIR}/Compiler/include
)

target_link_libraries(luau_runner PRIVATE
    Luau.Compiler
    Luau.VM
)
