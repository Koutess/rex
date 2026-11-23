// src/common/pipe.hpp
#pragma once
#include <windows.h>
#include <vector>
#include <optional>
#include <string>
#include "protocol.hpp"

namespace rex {
class PipeBase {
protected:
    HANDLE h_ = INVALID_HANDLE_VALUE;
    void close() {
        if (h_ != INVALID_HANDLE_VALUE) {
            CloseHandle(h_);
            h_ = INVALID_HANDLE_VALUE;
        }
    }
public:
    ~PipeBase() { close(); }
    
    bool write_packet(Cmd cmd, const void* data = nullptr, uint32_t size = 0) {
        PacketHeader hdr{};
        hdr.magic = MAGIC;
        hdr.cmd   = cmd;
        hdr.size  = size;
        hdr.crc   = data && size ? crc32(data, size) : 0;
        
        DWORD w = 0;
        if (!WriteFile(h_, &hdr, sizeof(hdr), &w, nullptr)) return false;
        if (size && data)
            return WriteFile(h_, data, size, &w, nullptr) != 0;
        return true;
    }
    
    std::optional<std::pair<Cmd, std::vector<uint8_t>>> read_packet() {
        PacketHeader hdr{};
        DWORD r = 0;
        if (!ReadFile(h_, &hdr, sizeof(hdr), &r, nullptr) || r != sizeof(hdr))
            return std::nullopt;
            
        if (hdr.magic != MAGIC) return std::nullopt;
        
        std::vector<uint8_t> body(hdr.size);
        if (hdr.size) {
            if (!ReadFile(h_, body.data(), hdr.size, &r, nullptr) || r != hdr.size)
                return std::nullopt;
            if (crc32(body.data(), body.size()) != hdr.crc)
                return std::nullopt;
        }
        return std::make_pair(hdr.cmd, std::move(body));
    }
};

class PipeServer : public PipeBase {
public:
    bool create(const char* name = PIPE_NAME) {
        h_ = CreateNamedPipeA(name, PIPE_ACCESS_DUPLEX,
                              PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                              1, 1<<20, 1<<20, 50, nullptr);
        return h_ != INVALID_HANDLE_VALUE;
    }
    bool wait_client() {
        return ConnectNamedPipe(h_, nullptr) || GetLastError() == ERROR_PIPE_CONNECTED;
    }
    void disconnect() { DisconnectNamedPipe(h_); }
};

class PipeClient : public PipeBase {
public:
    bool connect(const char* name = PIPE_NAME, DWORD timeout = 8000) {
        if (!WaitNamedPipeA(name, timeout)) return false;
        h_ = CreateFileA(name, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        return h_ != INVALID_HANDLE_VALUE;
    }
};
} // namespace rex
