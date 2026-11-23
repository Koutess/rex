#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

struct lua_State;

namespace rex::luau {

struct CompileOutput {
    bool ok = false;
    std::string bytecode;
    std::string error;
};

struct RunOutput {
    bool ok = false;
    std::string logs;
    std::string error;
};

class Runner {
public:
    Runner();
    ~Runner();

    Runner(const Runner&) = delete;
    Runner& operator=(const Runner&) = delete;

    static CompileOutput compile(std::string_view source, int opt_level = 1, int debug_level = 1);

    RunOutput run_bytecode(const uint8_t* data, size_t size, std::string_view chunk_name = "=chunk");
    RunOutput run_source(std::string_view source, std::string_view chunk_name = "=chunk",
                         int opt_level = 1, int debug_level = 1);

private:
    lua_State* L_ = nullptr;
    std::string current_logs_;

    void append_log(std::string_view prefix, std::string_view msg);
    static int lua_print_binding(lua_State* L);
    static int lua_warn_binding(lua_State* L);
};

} // namespace rex::luau
