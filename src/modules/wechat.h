#pragma once

#include "../module.h"

// WeChat module: AES-256-CBC + PBKDF2-HMAC-SHA1
// Key: 32 bytes binary, derived with 64000 iterations

extern const ChatModule wechat_module;
