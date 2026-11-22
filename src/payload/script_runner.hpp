// src/payload/script_runner.hpp
#pragma once
#include <string>
#include <cstdint>

namespace rex {

class ScriptRunner {
public:
    bool attach();
    std::string execute(const std::string& source);
    std::string execute_bytecode(const uint8_t* data, size_t size);
    void set_identity(int level);
    bool is_attached() const { return attached_; }

private:
    bool attached_ = false;
    uintptr_t script_context_ = 0;
    uintptr_t task_scheduler_ = 0;
    // function pointers resolved from patterns
    using load_fn = int(*)(void* L, const char* src, size_t len, const char* name);
    load_fn load_ = nullptr;
};

} // namespace rex
