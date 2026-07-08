#include "wechat_v4_bin.h"
#include "../common.h"

#include <cstdio>
#include <cstring>
#include <cctype>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

// WeChat 4.x binary key — 32-byte passphrase in process memory
// Algorithm from WeChatDataAnalysis key_v4.py is_ok():
//
//   derived_key = PBKDF2-SHA512(key, db_salt, 256000, 32)
//   hmac_key    = PBKDF2-SHA512(derived_key, db_salt^0x3A, 2, 32)
//   HMAC-SHA512(hmac_key, page[16:4032] + LE32(1)) == page[4032:4096]
//
// Decrypt: raw_key = x'<derived_key_hex><db_salt_hex>'
//   sqlcipher PRAGMA key = raw_key (raw key mode, no further PBKDF2)

#define WX4B_PAGE_SIZE       4096
#define WX4B_KEY_SIZE        32
#define WX4B_PROBE_SIZE      32
#define WX4B_SALT_SIZE       16
#define WX4B_IV_SIZE         16
#define WX4B_HMAC_SIZE       64   // HMAC-SHA512
#define WX4B_RESERVE_SZ      80
#define WX4B_KDF_ITER        256000
#define WX4B_FAST_ITER       2
#define WX4B_HMAC_SALT_MASK  0x3a
#define WX4B_PROGRESS_INTERVAL 2000

// Filter — matches wechat-decrypt key_v4.py is_potential_key()
// At least 15 unique bytes, at most 24 printable (32-126) chars
static bool wechat_v4_bin_filter(const uint8_t* data) {
    uint8_t freq[256] = {0};
    int unique = 0, printable = 0, zeros = 0;

    for (int i = 0; i < WX4B_KEY_SIZE; i++) {
        uint8_t c = data[i];
        if (c == 0) zeros++;
        if (freq[c] == 0) unique++;
        freq[c]++;
        if (c >= 32 && c <= 126) printable++;
    }

    // Not mostly zeros
    if (zeros > 28) return false;
    // At least 15 unique bytes (random crypto key)
    if (unique < 15) return false;
    // At most 24 printable chars (crypto keys are mostly non-printable)
    if (printable > 24) return false;
    return true;
}

static void wechat_v4_bin_extract_key(const uint8_t* probe, uint8_t* key_out) {
    memcpy(key_out, probe, WX4B_KEY_SIZE);
}

// Verify — matches key_v4.py is_ok() exactly
static bool wechat_v4_bin_verify(const uint8_t* key, const uint8_t* page_data, int page_size) {
    if (page_size < WX4B_PAGE_SIZE) return false;

    const uint8_t* passphrase = key;
    const uint8_t* salt = page_data;

    int hmac_data_len = WX4B_PAGE_SIZE - WX4B_RESERVE_SZ;
    const uint8_t* hmac_data = page_data + WX4B_SALT_SIZE;
    const uint8_t* stored_hmac = page_data + WX4B_PAGE_SIZE - WX4B_HMAC_SIZE;

    // Step 1: derived_key = PBKDF2-SHA512(passphrase, db_salt, 256000, 32)
    uint8_t derived_key[32];
    if (PKCS5_PBKDF2_HMAC((const char*)passphrase, WX4B_KEY_SIZE,
                          salt, WX4B_SALT_SIZE, WX4B_KDF_ITER,
                          EVP_sha512(), 32, derived_key) != 1)
        return false;

    // Step 2: hmac_key = PBKDF2-SHA512(derived_key, db_salt^0x3A, 2, 32)
    uint8_t mac_salt[WX4B_SALT_SIZE];
    for (int i = 0; i < WX4B_SALT_SIZE; i++)
        mac_salt[i] = salt[i] ^ WX4B_HMAC_SALT_MASK;

    uint8_t hmac_key[32];
    if (PKCS5_PBKDF2_HMAC((const char*)derived_key, 32,
                          mac_salt, WX4B_SALT_SIZE, WX4B_FAST_ITER,
                          EVP_sha512(), 32, hmac_key) != 1)
        return false;

    // Step 3: HMAC-SHA512(hmac_key, hmac_data + LE32(1))
    uint32_t pgno_le = 1;
    uint8_t computed[WX4B_HMAC_SIZE];
    unsigned int hlen = WX4B_HMAC_SIZE;

    HMAC_CTX* hctx = HMAC_CTX_new();
    HMAC_Init_ex(hctx, hmac_key, 32, EVP_sha512(), NULL);
    HMAC_Update(hctx, hmac_data, hmac_data_len);
    HMAC_Update(hctx, (const uint8_t*)&pgno_le, sizeof(pgno_le));
    HMAC_Final(hctx, computed, &hlen);
    HMAC_CTX_free(hctx);

    return (memcmp(computed, stored_hmac, WX4B_HMAC_SIZE) == 0);
}

// Decrypt: derive key, write SQL to temp file, use sqlcipher CLI with file input
static bool wechat_v4_bin_decrypt(const uint8_t* key, const char* input_path, const char* output_path) {
    uint8_t page[WX4B_PAGE_SIZE];
    FILE* f = fopen(input_path, "rb");
    if (!f) return false;
    fread(page, 1, WX4B_PAGE_SIZE, f);
    fclose(f);

    // Derive encryption key
    uint8_t dk[32];
    if (PKCS5_PBKDF2_HMAC((const char*)key, WX4B_KEY_SIZE,
                          page, WX4B_SALT_SIZE, WX4B_KDF_ITER,
                          EVP_sha512(), 32, dk) != 1)
        return false;

    // Construct raw key: x'<derived_key_hex><db_salt_hex>' (lowercase hex)
    char raw_key[256];
    int off = snprintf(raw_key, sizeof(raw_key), "x'");
    for (int i = 0; i < 32; i++)
        off += snprintf(raw_key + off, sizeof(raw_key) - off, "%02x", dk[i]);
    for (int i = 0; i < WX4B_SALT_SIZE; i++)
        off += snprintf(raw_key + off, sizeof(raw_key) - off, "%02x", page[i]);
    off += snprintf(raw_key + off, sizeof(raw_key) - off, "'");

    // Write SQL commands to temp file
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

    // Run sqlcipher with file input, pipe to sqlite3
    snprintf(cmd, sizeof(cmd),
        "sqlcipher \"%s\" < \"%s\" 2>/dev/null | tail -n +2 | sqlite3 \"%s\" 2>/dev/null",
        input_path, sql_path, output_path);
    system(cmd);
    delete_file(sql_path);

    return (get_file_size(output_path) > 0);
}

static void wechat_v4_bin_print_key(const uint8_t* key) {
    for (int i = 0; i < WX4B_KEY_SIZE; i++) printf("%02X", key[i]);
}

// YARA-style scan: find pointer structures, scan nearby for crypto keys
// Pattern: ?? ?? ?? ?? ?? ?? 00*10 20 00*7 2f 00*7
// The key is typically within a few MB of the YARA structure
static int wechat_v4_bin_scan_candidates(const uint8_t* dump, int64_t dump_size,
                                          uint8_t* key_buf, int max_keys) {
    const uint8_t needle[] = {
        0,0,0,0,0,0,0,0,0,0, 0x20, 0,0,0,0,0,0,0, 0x2f, 0,0,0,0,0,0,0
    };
    const int needle_len = sizeof(needle);

    int found = 0;
    for (int64_t pos = 0; pos < dump_size - needle_len - 8 && found < max_keys; pos++) {
        if (memcmp(dump + pos, needle, needle_len) != 0) continue;
        if (pos < 6) continue;

        // Scan a 64KB window around the match for 32-byte crypto keys
        int64_t start = pos - 6 - 32*1024;
        int64_t end   = pos + 32*1024;
        if (start < 0) start = 0;
        if (end > dump_size - WX4B_KEY_SIZE) end = dump_size - WX4B_KEY_SIZE;

        for (int64_t k = start; k <= end && found < max_keys; k += 1) {
            const uint8_t* c = dump + k;
            int unique = 0, printable = 0, zeros = 0;
            uint8_t freq[256] = {0};
            for (int i = 0; i < WX4B_KEY_SIZE; i++) {
                uint8_t b = c[i];
                if (b == 0) zeros++;
                if (freq[b] == 0) unique++;
                freq[b]++;
                if (b >= 32 && b <= 126) printable++;
            }
            // Reject zero-heavy and text-heavy: crypto keys have balanced distribution
            if (unique < 20 || printable > 20 || zeros > 8) continue;

            memcpy(key_buf + found * WX4B_KEY_SIZE, c, WX4B_KEY_SIZE);
            found++;
        }
        pos += needle_len;
    }
    return found;
}

const ChatModule wechat_v4_bin_module = {
    "wechat_v4_bin",
    "WeChat 4.x (bin)",
    WX4B_KEY_SIZE,
    WX4B_PROBE_SIZE,
    WX4B_PAGE_SIZE,
    WX4B_PROGRESS_INTERVAL,
    wechat_v4_bin_filter,
    wechat_v4_bin_extract_key,
    wechat_v4_bin_verify,
    wechat_v4_bin_decrypt,
    wechat_v4_bin_print_key,
    nullptr,
    nullptr,
    wechat_v4_bin_scan_candidates
};
