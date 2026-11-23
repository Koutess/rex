cmake_minimum_required(VERSION 3.20)
project(rex LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Injector executable
add_executable(rex
    src/injector/main.cpp
    src/injector/manual_map.cpp
    src/injector/ui.cpp
    src/common/process.hpp
    src/common/file_utils.hpp
    src/common/pipe.hpp
    src/common/protocol.hpp
)

target_include_directories(rex PRIVATE src)

# Payload DLL
add_library(payload SHARED
    src/payload/payload.cpp
    src/common/pipe.hpp
    src/common/protocol.hpp
)

target_include_directories(payload PRIVATE src)

# Set output names
set_target_properties(rex PROPERTIES OUTPUT_NAME "rex")
set_target_properties(payload PROPERTIES OUTPUT_NAME "payload")
