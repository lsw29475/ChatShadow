#pragma once
#include "../module.h"

// WeChat 4.x hex key module: 64 ASCII hex chars in process memory
// Hex-decodes to 32 bytes, then PBKDF2-SHA512-256000 for verification

extern const ChatModule wechat_v4_hex_module;
