#pragma once

#include "../module.h"

// WeChat 4.x module: SQLCipher 4 with raw key (WCDB format)
// Key: 48-byte hex ASCII string = 32B enc_key + 16B salt
// Format in memory: x'<64hex_enc><32hex_salt>'

extern const ChatModule wechat_v4_module;
