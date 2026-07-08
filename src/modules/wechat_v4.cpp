#include "wechat_v4.h"
#include "../common.h"

#include <cstdio>
#include <cstring>
#include <cctype>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

// WeChat 4.x (SQLCipher 4 with WCDB raw key)
// Reference: ylytdeng/wechat-decrypt key_scan_common.py
//
// WCDB caches raw key as: x'<64hex_enc_key><32hex_salt>'
// Total: x' + 96 hex + ' = 99 ASCII chars in memory
//
// Algorithm (verify_enc_key):
//   mac_salt = salt XOR 0x3A
//   mac_key  = PBKDF2-HMAC-SHA512(enc_key, mac_salt, 2, 32)
//   hmac_data = page1[16 : 4096-80+16] = page1[16:4032]  (4016 bytes: data+IV)
//   stored_hmac = page1[4096-64 : 4096] = page1[4032:4096]
//   HMAC-SHA512(mac_key, hmac_data + LE32(1)) == stored_hmac

#define WX4_PAGE_SIZE       4096
#define WX4_ENC_KEY_SIZE    32
#define WX4_SALT_SIZE       16
#define WX4_KEY_BIN_SIZE    (WX4_ENC_KEY_SIZE + WX4_SALT_SIZE)  // 48 bytes decoded
#define WX4_PROBE_SIZE      99   // x' + 96 hex + '
#define WX4_IV_SIZE         16
#define WX4_HMAC_SIZE       64   // HMAC-SHA512
#define WX4_RESERVE_SZ      80   // IV(16) + HMAC(64), block-aligned
#define WX4_FAST_ITER       2
#define WX4_HMAC_SALT_MASK  0x3a
#define WX4_PROGRESS_INTERVAL 5000

// Filter: check if probe looks like x'<hex...>'
// Matches x' followed by 64-192 hex chars followed by '
static bool wechat_v4_filter(const uint8_t* data) {
    // Must start with x'
    if (data[0] != 'x' || data[1] != '\'') return false;

    // Find closing quote and count hex chars
    int hex_count = 0;
    for (int i = 2; i < WX4_PROBE_SIZE; i++) {
        uint8_t c = data[i];
        if (c == '\'') {
            // Valid hex lengths: 64 (enc_key only) or 96 (enc_key+salt)
            return (hex_count == 64 || hex_count == 96);
        }
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
            hex_count++;
            if (hex_count > 192) return false;
        } else {
            return false;
        }
    }
    return false;  // no closing quote found
}

// Extract key from x'<hex>' probe:
// If 96 hex chars: hex-decode to 48 bytes (32 enc_key + 16 salt)
// If 64 hex chars: hex-decode to 32 bytes enc_key, salt = 0
static void wechat_v4_extract_key(const uint8_t* probe, uint8_t* key_out) {
    memset(key_out, 0, WX4_KEY_BIN_SIZE);
    int off = 2;  // skip x'
    int hex_len = 0;
    while (probe[off + hex_len] != '\'' && hex_len < 192) hex_len++;

    auto from_hex = [](uint8_t c) -> uint8_t {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return 0;
    };

    int bin_len = hex_len / 2;
    for (int i = 0; i < bin_len && i < WX4_KEY_BIN_SIZE; i++) {
        uint8_t h = probe[off + i * 2];
        uint8_t l = probe[off + i * 2 + 1];
        key_out[i] = (from_hex(h) << 4) | from_hex(l);
    }
}

// Verify — matches verify_enc_key() from key_scan_common.py exactly
static bool wechat_v4_verify(const uint8_t* key, const uint8_t* page_data, int page_size) {
    if (page_size < WX4_PAGE_SIZE) return false;

    // key[0..31] = enc_key, key[32..47] = salt (may be zero if only 64 hex)
    const uint8_t* enc_key = key;
    const uint8_t* key_salt = key + WX4_ENC_KEY_SIZE;

    // Page layout (SQLCipher 4, reserve=80):
    //   [0..15]     salt from DB
    //   [16..4031]  ciphertext (4016 bytes = 4096-16-80+16? no, let me recalculate)

    // From the Python code:
    //   hmac_data = db_page1[SALT_SZ : PAGE_SZ - 80 + 16]
    //   = db_page1[16 : 4096 - 80 + 16] = db_page1[16 : 4032]
    //   That's 4016 bytes: ciphertext(4000) + IV(16)

    //   stored_hmac = db_page1[PAGE_SZ - 64 : PAGE_SZ]
    //   = db_page1[4032 : 4096] = 64 bytes

    int hmac_data_len = WX4_PAGE_SIZE - WX4_RESERVE_SZ;  // 4096-80 = 4016
    const uint8_t* hmac_data = page_data + WX4_SALT_SIZE;  // skip DB salt
    const uint8_t* stored_hmac = page_data + WX4_PAGE_SIZE - WX4_HMAC_SIZE;

    // Derive HMAC key: mac_salt = salt ^ 0x3A
    uint8_t mac_salt[WX4_SALT_SIZE];
    for (int i = 0; i < WX4_SALT_SIZE; i++)
        mac_salt[i] = key_salt[i] ^ WX4_HMAC_SALT_MASK;

    // mac_key = PBKDF2-HMAC-SHA512(enc_key, mac_salt, 2, 32)
    uint8_t mac_key[32];
    if (PKCS5_PBKDF2_HMAC((const char*)enc_key, WX4_ENC_KEY_SIZE,
                          mac_salt, WX4_SALT_SIZE, WX4_FAST_ITER,
                          EVP_sha512(), 32, mac_key) != 1)
        return false;

    // HMAC-SHA512(mac_key, hmac_data + LE32(1))
    uint32_t pgno_le = 1;
    uint8_t computed[WX4_HMAC_SIZE];
    unsigned int hlen = WX4_HMAC_SIZE;

    HMAC_CTX* hctx = HMAC_CTX_new();
    HMAC_Init_ex(hctx, mac_key, 32, EVP_sha512(), NULL);
    HMAC_Update(hctx, hmac_data, hmac_data_len);
    HMAC_Update(hctx, (const uint8_t*)&pgno_le, sizeof(pgno_le));
    HMAC_Final(hctx, computed, &hlen);
    HMAC_CTX_free(hctx);

    return (memcmp(computed, stored_hmac, WX4_HMAC_SIZE) == 0);
}

static bool wechat_v4_decrypt(const uint8_t* key, const char* input_path, const char* output_path) {
    char key_hex[256];
    int off = snprintf(key_hex, sizeof(key_hex), "x'");
    for (int i = 0; i < WX4_KEY_BIN_SIZE; i++)
        off += snprintf(key_hex + off, sizeof(key_hex) - off, "%02X", key[i]);
    off += snprintf(key_hex + off, sizeof(key_hex) - off, "'");

    char cmd[4096];
    snprintf(cmd, sizeof(cmd),
        "sqlcipher \"%s\" \"PRAGMA key = \\\"%s\\\";\" .dump 2>/dev/null | sqlite3 \"%s\" 2>/dev/null",
        input_path, key_hex, output_path);
    system(cmd);
    return (get_file_size(output_path) > 0);
}

static void wechat_v4_print_key(const uint8_t* key) {
    printf("x'");
    for (int i = 0; i < WX4_KEY_BIN_SIZE; i++) printf("%02X", key[i]);
    printf("'");
}

const ChatModule wechat_v4_module = {
    "wechat_v4",
    "WeChat 4.x",
    WX4_KEY_BIN_SIZE,
    WX4_PROBE_SIZE,
    WX4_PAGE_SIZE,
    WX4_PROGRESS_INTERVAL,
    wechat_v4_filter,
    wechat_v4_extract_key,
    wechat_v4_verify,
    wechat_v4_decrypt,
    wechat_v4_print_key,
    nullptr,   // init
    nullptr,   // cleanup
    nullptr    // scan_candidates
};
