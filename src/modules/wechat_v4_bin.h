#pragma once
#include "../module.h"

// WeChat 4.x binary key module: 32-byte raw enc_key in memory
// Salt comes from DB page, not from key

extern const ChatModule wechat_v4_bin_module;
