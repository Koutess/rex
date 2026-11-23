#include "luau_runner.hpp"
#include <iostream>

int main() {
    rex::luau::Runner runner;

    auto res1 = runner.run_source(R"(
        local x = 6 * 7
        print("answer =", x)
        warn("low fuel")
    )", "=test_script");

    std::cout << "ok=" << res1.ok << "\n";
    if (!res1.logs.empty()) {
        std::cout << "logs:\n" << res1.logs;
    }
    if (!res1.error.empty()) {
        std::cout << "error: " << res1.error << "\n";
    }

    // Verify direct bytecode path
    auto compiled = rex::luau::Runner::compile(R"(return 123)", 1, 1);
    if (compiled.ok) {
        auto res2 = runner.run_bytecode(
            reinterpret_cast<const uint8_t*>(compiled.bytecode.data()),
            compiled.bytecode.size(),
            "=raw_bc"
        );
        std::cout << "bytecode run ok=" << res2.ok << "\n";
    }

    return (res1.ok && compiled.ok) ? 0 : 1;
}
