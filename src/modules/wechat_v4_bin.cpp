#include "wechat_v4_bin.h"
#include "../common.h"

#include <cstdio>
#include <cstring>
#include <cctype>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

// WeChat 4.x binary key
// Algorithm reverse-engineered from Weixin.dll:
//   internal_key (32B, hardcoded in DLL) XOR mem_data (32B) → passphrase
//   derived_key = PBKDF2-SHA512(passphrase, db_salt, 256000, 32)
//   hmac_key    = PBKDF2-SHA512(derived_key, db_salt^0x3A, 2, 32)
//   HMAC-SHA512(hmac_key, page[16:4032] + LE32(1)) == page[4032:4096]

#define WX4B_PAGE_SIZE       4096
#define WX4B_KEY_SIZE        32
#define WX4B_PROBE_SIZE      32
#define WX4B_SALT_SIZE       16
#define WX4B_IV_SIZE         16
#define WX4B_HMAC_SIZE       64
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

// Hardcoded 32-byte internal key extracted from Weixin.dll at VA 0x18033C887
// Hardcoded 32-byte internal key extracted from Weixin.dll at VA 0x18033C887
// This is the default; can be overridden via -K <dll_path>
static uint8_t WX4B_INTERNAL_KEY[32] = {
    0xe5,0x3b,0x45,0xdd,0xbb,0x81,0x62,0xe1,
    0xd1,0x39,0x4a,0x4c,0x61,0x9a,0xd0,0xae,
    0x27,0xf0,0x20,0x7f,0xec,0x4b,0x35,0xa8,
    0xfa,0x79,0xf6,0x2c,0x6e,0x2e,0x7c,0xe7
};

// Forward decl
static int scan_window_to(const uint8_t* dump, int64_t dump_size, int64_t center,
                        int window, uint8_t* key_buf, int max_keys);

// Scan: try full marker first, then fragments. All hits contribute candidates.
static int wechat_v4_bin_scan_candidates(const uint8_t* dump, int64_t dump_size,
                                          uint8_t* key_buf, int max_keys) {
    const int window_full = 2 * 1024;

    const char* markers[] = {
        "g_voice_input_show_note_placeholder_text_count",
        "g_voice_input_show_note_placeholder_text",
    };

    int found = 0;

    // Scan full markers
    for (int m = 0; m < 2 && found < max_keys; m++) {
        int ml = strlen(markers[m]);
        for (int64_t pos = 0; pos < dump_size - ml && found < max_keys; pos++) {
            if (memcmp(dump + pos, markers[m], ml) != 0) continue;
            found += scan_window_to(dump, dump_size, pos, window_full,
                                    key_buf + found * WX4B_KEY_SIZE, max_keys - found);
        }
    }
    printf("YARA scan full markers found=%d\n", found);

    // clicfg_xwechat — high frequency, forward-only 5KB window
    {
        const char* clicfg = "clicfg_xwechat";
        int cl = strlen(clicfg);
        const int fwd = 1 * 512;
        for (int64_t pos = 0; pos < dump_size - cl && found < max_keys; pos++) {
            if (memcmp(dump + pos, clicfg, cl) != 0) continue;
            int64_t end = pos + fwd;
            if (end > dump_size - WX4B_KEY_SIZE) end = dump_size - WX4B_KEY_SIZE;
            for (int64_t k = pos; k <= end && found < max_keys; k += 1) {
                const uint8_t* c = dump + k;
                uint8_t freq[256] = {0}; bool dup = false;
                for (int i = 0; i < WX4B_KEY_SIZE && !dup; i++)
                    if (++freq[c[i]] >= 3) dup = true;
                if (dup) continue;
                for (int i = 0; i < WX4B_KEY_SIZE; i++)
                    key_buf[found * WX4B_KEY_SIZE + i] = c[i] ^ WX4B_INTERNAL_KEY[i];
                found++;
            }
        }
    }
    printf("YARA scan clicfg_xwechat found=%d\n", found);

    return found;  // total candidates from all phases
}

// Helper: scan window around position, write to buf, return count
static int scan_window_to(const uint8_t* dump, int64_t dump_size, int64_t center,
                        int window, uint8_t* key_buf, int max_keys) {
    int64_t start = center - window;
    int64_t end   = center + window;
    if (start < 0) start = 0;
    if (end > dump_size - WX4B_KEY_SIZE) end = dump_size - WX4B_KEY_SIZE;

    int found = 0;
    for (int64_t k = start; k <= end && found < max_keys; k += 1) {
        const uint8_t* c = dump + k;
        uint8_t freq[256] = {0};
        bool dup = false;
        for (int i = 0; i < WX4B_KEY_SIZE && !dup; i++)
            if (++freq[c[i]] >= 3) dup = true;
        if (dup) continue;

        for (int i = 0; i < WX4B_KEY_SIZE; i++)
            key_buf[found * WX4B_KEY_SIZE + i] = c[i] ^ WX4B_INTERNAL_KEY[i];
        found++;
    }
    return found;
}

// DLL key extraction: scan for 4× mov rdx,imm64 + test rax,rax
static bool wechat_v4_bin_init_from_dll(const char* dll_path) {
    int64_t sz; uint8_t* data;
    sz = read_file(dll_path, &data);
    if (sz < 0 || !data) { fprintf(stderr, "Cannot read DLL: %s\n", dll_path); return false; }
    for (int64_t i = 0; i < sz - 80LL; i++) {
        if (data[i] != 0x48 || data[i+1] != 0xBA) continue;
        int64_t pos = i; uint8_t key[32]; int n = 0;
        for (int g = 0; g < 4 && pos < sz - 10; g++) {
            if (data[pos] != 0x48 || data[pos+1] != 0xBA) break;
            memcpy(key + g*8, data+pos+2, 8); pos += 10;
            while (pos < sz-2 && !(data[pos]==0x48&&data[pos+1]==0xBA) && !(data[pos]==0x48&&data[pos+1]==0x85) && (pos-i)<80) pos++;
            n++;
        }
        if (n==4 && pos<sz-3 && data[pos]==0x48 && data[pos+1]==0x85 && data[pos+2]==0xC0) {
            memcpy(WX4B_INTERNAL_KEY, key, 32); free(data);
            printf("DLL key: "); for(int j=0;j<32;j++)printf("%02X",WX4B_INTERNAL_KEY[j]); printf("\n");
            return true;
        }
    }
    free(data); fprintf(stderr, "Cannot find internal key in DLL\n"); return false;
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
    wechat_v4_bin_scan_candidates,
    wechat_v4_bin_init_from_dll
};
