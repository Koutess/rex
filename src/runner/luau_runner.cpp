#include "luau_runner.hpp"

#include "lua.h"
#include "lualib.h"
#include "luacode.h"

#include <cstdlib>
#include <utility>

namespace rex::luau {

Runner::Runner() {
    L_ = luaL_newstate();
    if (!L_) {
        std::abort();
    }

    luaL_openlibs(L_);

    // Store `this` in registry so bound print/warn append to current_logs_
    lua_pushlightuserdata(L_, this);
    lua_setfield(L_, LUA_REGISTRYINDEX, "rex_runner_ptr");

    lua_pushcfunction(L_, lua_print_binding, "print");
    lua_setglobal(L_, "print");

    lua_pushcfunction(L_, lua_warn_binding, "warn");
    lua_setglobal(L_, "warn");
}

Runner::~Runner() {
    if (L_) {
        lua_close(L_);
        L_ = nullptr;
    }
}

void Runner::append_log(std::string_view prefix, std::string_view msg) {
    current_logs_.append(prefix);
    current_logs_.append(msg);
    current_logs_.push_back('\n');
}

int Runner::lua_print_binding(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, "rex_runner_ptr");
    auto* self = static_cast<Runner*>(lua_touserdata(L, -1));
    lua_pop(L, 1);

    int nargs = lua_gettop(L);
    std::string line;

    lua_getglobal(L, "tostring");
    for (int i = 1; i <= nargs; ++i) {
        if (i > 1) {
            line.push_back('\t');
        }
        lua_pushvalue(L, -1); // tostring
        lua_pushvalue(L, i);  // arg i
        lua_call(L, 1, 1);
        size_t len = 0;
        const char* s = lua_tolstring(L, -1, &len);
        if (s) {
            line.append(s, len);
        }
        lua_pop(L, 1); // pop string result
    }
    lua_pop(L, 1); // pop tostring

    if (self) {
        self->append_log("", line);
    }
    return 0;
}

int Runner::lua_warn_binding(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, "rex_runner_ptr");
    auto* self = static_cast<Runner*>(lua_touserdata(L, -1));
    lua_pop(L, 1);

    int nargs = lua_gettop(L);
    std::string line;

    lua_getglobal(L, "tostring");
    for (int i = 1; i <= nargs; ++i) {
        if (i > 1) {
            line.push_back(' ');
        }
        lua_pushvalue(L, -1);
        lua_pushvalue(L, i);
        lua_call(L, 1, 1);
        size_t len = 0;
        const char* s = lua_tolstring(L, -1, &len);
        if (s) {
            line.append(s, len);
        }
        lua_pop(L, 1);
    }
    lua_pop(L, 1);

    if (self) {
        self->append_log("[warn] ", line);
    }
    return 0;
}

CompileOutput Runner::compile(std::string_view source, int opt_level, int debug_level) {
    CompileOutput out{};

    lua_CompileOptions opts{};
    opts.optimizationLevel = opt_level;
    opts.debugLevel = debug_level;

    size_t bytecode_size = 0;
    char* raw = luau_compile(source.data(), source.size(), &opts, &bytecode_size);
    if (!raw || bytecode_size == 0) {
        if (raw) {
            free(raw);
        }
        out.error = "luau_compile returned empty bytecode";
        return out;
    }

    // Luau's compiler encodes compile errors in bytecode starting with a null byte (0x00)
    if (raw[0] == '\0') {
        out.error.assign(raw + 1, bytecode_size > 1 ? bytecode_size - 1 : 0);
        free(raw);
        return out;
    }

    out.bytecode.assign(raw, bytecode_size);
    free(raw);
    out.ok = true;
    return out;
}

RunOutput Runner::run_bytecode(const uint8_t* data, size_t size, std::string_view chunk_name) {
    RunOutput out{};
    current_logs_.clear();

    if (!data || size == 0) {
        out.error = "empty bytecode buffer";
        return out;
    }

    const int base_top = lua_gettop(L_);
    std::string chunk_str(chunk_name);

    // env = 0 uses the current thread's global environment
    int load_status = luau_load(
        L_,
        chunk_str.c_str(),
        reinterpret_cast<const char*>(data),
        size,
        0
    );

    if (load_status != 0) {
        size_t err_len = 0;
        const char* err = lua_tolstring(L_, -1, &err_len);
        out.error = err ? std::string(err, err_len) : "luau_load failed";
        out.logs = std::move(current_logs_);
        lua_settop(L_, base_top);
        return out;
    }

    int call_status = lua_pcall(L_, 0, LUA_MULTRET, 0);
    if (call_status != LUA_OK) {
        size_t err_len = 0;
        const char* err = lua_tolstring(L_, -1, &err_len);
        out.error = err ? std::string(err, err_len) : "lua_pcall runtime error";
        out.logs = std::move(current_logs_);
        lua_settop(L_, base_top);
        return out;
    }

    out.ok = true;
    out.logs = std::move(current_logs_);
    lua_settop(L_, base_top);
    return out;
}

RunOutput Runner::run_source(std::string_view source, std::string_view chunk_name,
                             int opt_level, int debug_level) {
    auto compiled = compile(source, opt_level, debug_level);
    if (!compiled.ok) {
        return RunOutput{ false, {}, std::move(compiled.error) };
    }

    return run_bytecode(
        reinterpret_cast<const uint8_t*>(compiled.bytecode.data()),
        compiled.bytecode.size(),
        chunk_name
    );
}

} // namespace rex::luau
