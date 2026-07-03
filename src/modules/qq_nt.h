#pragma once

#include "../module.h"

// NTQQ (New QQ Architecture) module: SQLCipher / AES-256-CBC + PBKDF2-HMAC-SHA512
// Key: 32-byte ASCII string (printable characters 0x20-0x7E)
// Database has 1024-byte header prefix before SQLCipher data

extern const ChatModule qq_nt_module;
