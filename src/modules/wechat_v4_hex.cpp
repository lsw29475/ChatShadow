#include "wechat_v4_hex.h"
#include "../common.h"

#include <cstdio>
#include <cstring>
#include <cctype>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

// WeChat 4.x hex-AES key — 64 ASCII hex chars in process memory
// Algorithm:
//   bin_key = hex_decode(probe) → 32 bytes
//   Verify: PBKDF2-SHA512(bin_key, db_salt, 256000) → HMAC check

#define WX4H_PAGE_SIZE       4096
#define WX4H_KEY_BIN_SIZE    32
#define WX4H_PROBE_SIZE      64   // 64 hex chars in memory
#define WX4H_SALT_SIZE       16
#define WX4H_IV_SIZE         16
#define WX4H_HMAC_SIZE       64
#define WX4H_RESERVE_SZ      80
#define WX4H_KDF_ITER        256000
#define WX4H_FAST_ITER       2
#define WX4H_HMAC_SALT_MASK  0x3a
#define WX4H_PROGRESS_INTERVAL 5000

// Filter: 64 consecutive ASCII hex chars [0-9a-fA-F]
static bool wechat_v4_hex_filter(const uint8_t* data) {
    int digits = 0, upper = 0, lower = 0;
    uint8_t freq[256] = {0};
    int max_freq = 0;

    for (int i = 0; i < WX4H_PROBE_SIZE; i++) {
        uint8_t c = data[i];
        if (c >= '0' && c <= '9') digits++;
        else if (c >= 'A' && c <= 'F') upper++;
        else if (c >= 'a' && c <= 'f') lower++;
        else return false;

        int f = ++freq[c];
        if (f > max_freq) max_freq = f;
    }

    // Not all same char
    if (max_freq > 55) return false;
    // Must have at least 2 char types
    if ((digits > 0) + (upper > 0) + (lower > 0) < 2) return false;
    return true;
}

// Hex decode 64 chars → 32 bytes
static void wechat_v4_hex_extract_key(const uint8_t* probe, uint8_t* key_out) {
    auto from_hex = [](uint8_t c) -> uint8_t {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return 0;
    };
    for (int i = 0; i < WX4H_KEY_BIN_SIZE; i++)
        key_out[i] = (from_hex(probe[i*2]) << 4) | from_hex(probe[i*2+1]);
}

// Verify — same as wechat_v4_bin
static bool wechat_v4_hex_verify(const uint8_t* key, const uint8_t* page_data, int page_size) {
    if (page_size < WX4H_PAGE_SIZE) return false;

    const uint8_t* passphrase = key;
    const uint8_t* salt = page_data;

    int hmac_data_len = WX4H_PAGE_SIZE - WX4H_RESERVE_SZ;
    const uint8_t* hmac_data = page_data + WX4H_SALT_SIZE;
    const uint8_t* stored_hmac = page_data + WX4H_PAGE_SIZE - WX4H_HMAC_SIZE;

    uint8_t derived_key[32];
    if (PKCS5_PBKDF2_HMAC((const char*)passphrase, WX4H_KEY_BIN_SIZE,
                          salt, WX4H_SALT_SIZE, WX4H_KDF_ITER,
                          EVP_sha512(), 32, derived_key) != 1)
        return false;

    uint8_t mac_salt[WX4H_SALT_SIZE];
    for (int i = 0; i < WX4H_SALT_SIZE; i++)
        mac_salt[i] = salt[i] ^ WX4H_HMAC_SALT_MASK;

    uint8_t hmac_key[32];
    if (PKCS5_PBKDF2_HMAC((const char*)derived_key, 32,
                          mac_salt, WX4H_SALT_SIZE, WX4H_FAST_ITER,
                          EVP_sha512(), 32, hmac_key) != 1)
        return false;

    uint32_t pgno_le = 1;
    uint8_t computed[WX4H_HMAC_SIZE];
    unsigned int hlen = WX4H_HMAC_SIZE;

    HMAC_CTX* hctx = HMAC_CTX_new();
    HMAC_Init_ex(hctx, hmac_key, 32, EVP_sha512(), NULL);
    HMAC_Update(hctx, hmac_data, hmac_data_len);
    HMAC_Update(hctx, (const uint8_t*)&pgno_le, sizeof(pgno_le));
    HMAC_Final(hctx, computed, &hlen);
    HMAC_CTX_free(hctx);

    return (memcmp(computed, stored_hmac, WX4H_HMAC_SIZE) == 0);
}

// Decrypt same as wechat_v4_bin
static bool wechat_v4_hex_decrypt(const uint8_t* key, const char* input_path, const char* output_path) {
    uint8_t page[WX4H_PAGE_SIZE];
    FILE* f = fopen(input_path, "rb");
    if (!f) return false;
    fread(page, 1, WX4H_PAGE_SIZE, f);
    fclose(f);

    uint8_t dk[32];
    if (PKCS5_PBKDF2_HMAC((const char*)key, WX4H_KEY_BIN_SIZE,
                          page, WX4H_SALT_SIZE, WX4H_KDF_ITER,
                          EVP_sha512(), 32, dk) != 1)
        return false;

    char raw_key[256];
    int off = snprintf(raw_key, sizeof(raw_key), "x'");
    for (int i = 0; i < 32; i++)
        off += snprintf(raw_key + off, sizeof(raw_key) - off, "%02x", dk[i]);
    for (int i = 0; i < WX4H_SALT_SIZE; i++)
        off += snprintf(raw_key + off, sizeof(raw_key) - off, "%02x", page[i]);
    off += snprintf(raw_key + off, sizeof(raw_key) - off, "'");

    char sql_path[256], cmd[4096];
    snprintf(sql_path, sizeof(sql_path), "/tmp/chatshadow_wx_%d.sql", getpid());
    FILE* sf = fopen(sql_path, "w");
    if (!sf) return false;
    fprintf(sf, "PRAGMA cipher_hmac_algorithm = HMAC_SHA512;\n");
    fprintf(sf, "PRAGMA kdf_iter = 256000;\n");
    fprintf(sf, "PRAGMA cipher_page_size = 4096;\n");
    fprintf(sf, "PRAGMA key = \"%s\";\n", raw_key);
    fprintf(sf, ".dump\n.quit\n");
    fclose(sf);

    snprintf(cmd, sizeof(cmd),
        "sqlcipher \"%s\" < \"%s\" 2>/dev/null | tail -n +2 | sqlite3 \"%s\" 2>/dev/null",
        input_path, sql_path, output_path);
    system(cmd);
    delete_file(sql_path);

    return (get_file_size(output_path) > 0);
}

static void wechat_v4_hex_print_key(const uint8_t* key) {
    for (int i = 0; i < WX4H_KEY_BIN_SIZE; i++) printf("%02X", key[i]);
}

const ChatModule wechat_v4_hex_module = {
    "wechat_v4_hex",
    "WeChat 4.x (hex)",
    WX4H_KEY_BIN_SIZE,
    WX4H_PROBE_SIZE,
    WX4H_PAGE_SIZE,
    WX4H_PROGRESS_INTERVAL,
    wechat_v4_hex_filter,
    wechat_v4_hex_extract_key,
    wechat_v4_hex_verify,
    wechat_v4_hex_decrypt,
    wechat_v4_hex_print_key,
    nullptr,   // init
    nullptr,   // cleanup
    nullptr    // scan_candidates
};
