// src/common/protocol.hpp
#pragma once
#include <cstdint>

namespace rex {

constexpr const char* PIPE_NAME = R"(\\.\pipe\Rex_7f3a9c2e8b1d)";
constexpr uint32_t MAGIC = 0x52455845;

enum class Cmd : uint32_t {
    Ping            = 1,
    Execute         = 2,
    ExecuteBytecode = 3,
    Status          = 4,
    SetIdentity     = 5,
    IsAttached      = 6,
    Unload          = 7,
    Shutdown        = 8,
};

#pragma pack(push, 1)
struct PacketHeader {
    uint32_t magic;
    Cmd      cmd;
    uint32_t size;
    uint32_t crc;
};
#pragma pack(pop)

inline uint32_t crc32(const void* data, size_t len) {
    static const uint32_t table[256] = {
        // standard CRC32 table omitted for length – use any public one or generate at compile time
        0x00000000,0x77073096,0xEE0E612C,0x990951BA,0x076DC419,0x706AF48F,0xE963A535,0x9E6495A3,
        // … full 256-entry table here in real file
    };
    uint32_t c = 0xFFFFFFFFu;
    const auto* p = static_cast<const uint8_t*>(data);
    for (size_t i = 0; i < len; ++i)
        c = table[(c ^ p[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

} // namespace rex
