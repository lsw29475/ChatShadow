#include "qq_nt.h"
#include "../common.h"

#include <cstdio>
#include <cstring>
#include <cctype>
#include <unistd.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

// NTQQ encryption parameters (SQLCipher 4)
#define QQ_NT_KEY_SIZE        16
#define QQ_NT_PROBE_SIZE      16
#define QQ_NT_PAGE_SIZE       4096
#define QQ_NT_HEADER_SIZE     1024
#define QQ_NT_SALT_SIZE       16
#define QQ_NT_IV_SIZE         16
#define QQ_NT_HMAC_SIZE       20   // HMAC_SHA1
#define QQ_NT_BLOCK_SIZE      16
#define QQ_NT_ITER            4000
#define QQ_NT_FAST_ITER       2
#define QQ_NT_HMAC_SALT_MASK  0x3a
#define QQ_NT_RESERVE_SZ      (((QQ_NT_IV_SIZE + QQ_NT_HMAC_SIZE + QQ_NT_BLOCK_SIZE - 1) / QQ_NT_BLOCK_SIZE) * QQ_NT_BLOCK_SIZE)
#define QQ_NT_DATA_LEN        (QQ_NT_PAGE_SIZE - QQ_NT_SALT_SIZE - QQ_NT_RESERVE_SZ)
#define QQ_NT_PROGRESS_INTERVAL 5000

static bool qq_nt_filter(const uint8_t* data) {
    int upper = 0, lower = 0, digit = 0, punct = 0;
    int vowels = 0;
    uint8_t freq[256] = {0};
    int max_freq = 0;

    for (int i = 0; i < QQ_NT_KEY_SIZE; i++) {
        uint8_t c = data[i];
        if (c < 0x21 || c > 0x7E) return false;
        int f = ++freq[c]; if (f > max_freq) max_freq = f;
        if (c >= 'A' && c <= 'Z') { upper++; if (c == 'A'||c == 'E'||c == 'I'||c == 'O'||c == 'U') vowels++; }
        else if (c >= 'a' && c <= 'z') { lower++; if (c == 'a'||c == 'e'||c == 'i'||c == 'o'||c == 'u') vowels++; }
        else if (c >= '0' && c <= '9') digit++;
        else punct++;
    }
    int types = (upper > 0) + (lower > 0) + (digit > 0) + (punct > 0);
    if (types < 2) return false;
    if (upper + lower > 13) return false;
    if (digit > 13) return false;
    if (punct > 6) return false;
    if (max_freq > 4) return false;
    if (vowels >= 6) return false;

    int max_run = 0, cur_run = 0, prev_type = -1;
    int slashes = 0, dots = 0, colons = 0, equals = 0, pluses = 0;
    for (int i = 0; i < QQ_NT_KEY_SIZE; i++) {
        uint8_t c = data[i];
        int ct = (c>='a'&&c<='z')?0:(c>='A'&&c<='Z')?1:(c>='0'&&c<='9')?2:3;
        if (c == '/' || c == '\\') slashes++;
        if (c == '.') dots++; if (c == ':') colons++; if (c == '=') equals++; if (c == '+') pluses++;
        if (ct == prev_type) { cur_run++; if (cur_run > max_run) max_run = cur_run; }
        else { cur_run = 1; prev_type = ct; }
    }
    if (max_run >= 5) return false;
    if (slashes >= 2 || colons >= 2 || dots >= 4 || equals >= 2 || pluses >= 2) return false;

    static const char* bad[] = {"the","and","ing","tion","for","that","with"};
    for (int w = 0; w < 7; w++) {
        int wl = strlen(bad[w]);
        for (int i = 0; i <= QQ_NT_KEY_SIZE - wl; i++) {
            bool match = true;
            for (int j = 0; j < wl; j++)
                if (data[i+j] != bad[w][j] && data[i+j] != bad[w][j]-32) { match = false; break; }
            if (match) return false;
        }
    }
    return true;
}

static void qq_nt_extract_key(const uint8_t* probe, uint8_t* key_out) {
    memcpy(key_out, probe, QQ_NT_KEY_SIZE);
}

// Verify using pure OpenSSL — matches sqlcipher 4.x algorithm exactly
static bool qq_nt_verify(const uint8_t* key, const uint8_t* page_data, int page_size) {
    if (page_size < QQ_NT_PAGE_SIZE) return false;

    // SQLCipher 4 page layout (after salt at bytes 0-15):
    //   bytes 0..4031: ciphertext (QQ_NT_DATA_LEN = 4032)
    //   bytes 4032..4047: IV (16)
    //   bytes 4048..4067: HMAC-SHA1 (20)
    //   bytes 4068..4095: random padding (12)
    // Total after salt: 48 = QQ_NT_RESERVE_SZ (rounded to AES block)
    const uint8_t* salt = page_data;
    const uint8_t* ct = page_data + QQ_NT_SALT_SIZE;
    const uint8_t* iv_in_page = ct + QQ_NT_DATA_LEN;
    const uint8_t* stored_hmac = iv_in_page + QQ_NT_IV_SIZE;

    // Step 1: derive encryption key via PBKDF2-HMAC-SHA512(password, salt, 4000)
    uint8_t enc_key[32];
    if (PKCS5_PBKDF2_HMAC((const char*)key, QQ_NT_KEY_SIZE,
                          salt, QQ_NT_SALT_SIZE, QQ_NT_ITER,
                          EVP_sha512(), 32, enc_key) != 1)
        return false;

    // Step 2: derive HMAC key from encryption key
    // salt_hmac = salt XOR hmac_salt_mask (0x3a)
    uint8_t hmac_salt[QQ_NT_SALT_SIZE];
    for (int i = 0; i < QQ_NT_SALT_SIZE; i++)
        hmac_salt[i] = salt[i] ^ QQ_NT_HMAC_SALT_MASK;

    uint8_t hmac_key[32];
    if (PKCS5_PBKDF2_HMAC((const char*)enc_key, 32,
                          hmac_salt, QQ_NT_SALT_SIZE, QQ_NT_FAST_ITER,
                          EVP_sha512(), 32, hmac_key) != 1)
        return false;

    // Step 3: HMAC-SHA1 over (ciphertext + IV + page_number_LE)
    uint32_t pgno_le = 1;  // x86 native = little-endian
    uint8_t computed[QQ_NT_HMAC_SIZE];
    unsigned int hlen = QQ_NT_HMAC_SIZE;

    HMAC_CTX* hctx = HMAC_CTX_new();
    HMAC_Init_ex(hctx, hmac_key, 32, EVP_sha1(), NULL);
    HMAC_Update(hctx, ct, QQ_NT_DATA_LEN);
    HMAC_Update(hctx, iv_in_page, QQ_NT_IV_SIZE);
    HMAC_Update(hctx, (const uint8_t*)&pgno_le, sizeof(pgno_le));
    HMAC_Final(hctx, computed, &hlen);
    HMAC_CTX_free(hctx);

    return (memcmp(computed, stored_hmac, QQ_NT_HMAC_SIZE) == 0);
}

// Decrypt using sqlcipher CLI
static bool qq_nt_decrypt(const uint8_t* key, const char* input_path, const char* output_path) {
    std::string clean_path = "/tmp/chatshadow_dec_" + std::to_string(getpid()) + ".db";
    
    char cmd[4096];
    snprintf(cmd, sizeof(cmd), "tail -c +%d \"%s\" > \"%s\" 2>/dev/null",
             QQ_NT_HEADER_SIZE + 1, input_path, clean_path.c_str());
    if (system(cmd) != 0) {
        snprintf(cmd, sizeof(cmd), "dd if=\"%s\" of=\"%s\" bs=1 skip=%d 2>/dev/null",
                 input_path, clean_path.c_str(), QQ_NT_HEADER_SIZE);
        system(cmd);
    }

    char key_str[17]; memcpy(key_str, key, 16); key_str[16] = '\0';
    char escaped[128]; int j = 0;
    for (int i = 0; i < 16 && key_str[i]; i++) {
        if (key_str[i] == '\'') { escaped[j++] = '\''; escaped[j++] = '\\'; escaped[j++] = '\''; }
        escaped[j++] = key_str[i];
    }
    escaped[j] = '\0';

    snprintf(cmd, sizeof(cmd),
        "sqlcipher \"%s\" \"PRAGMA key = '%s'; "
        "PRAGMA cipher_hmac_algorithm = HMAC_SHA1; "
        "PRAGMA kdf_iter = 4000; "
        "PRAGMA cipher_page_size = 4096;\" "
        ".dump 2>/dev/null | sqlite3 \"%s\" 2>/dev/null",
        clean_path.c_str(), escaped, output_path);

    system(cmd);
    delete_file(clean_path.c_str());
    return (get_file_size(output_path) > 0);
}

static void qq_nt_print_key(const uint8_t* key) {
    for (int i = 0; i < 16; i++) printf("%c", key[i]);
}

static void qq_nt_init(const char* db_path) { /* no-op for pure algo */ }
static void qq_nt_cleanup() { /* no-op */ }

const ChatModule qq_nt_module = {
    "qq_nt",
    "QQ (NT/New)",
    QQ_NT_KEY_SIZE,
    QQ_NT_PROBE_SIZE,
    QQ_NT_PAGE_SIZE,
    QQ_NT_PROGRESS_INTERVAL,
    qq_nt_filter,
    qq_nt_extract_key,
    qq_nt_verify,
    qq_nt_decrypt,
    qq_nt_print_key,
    qq_nt_init,
    qq_nt_cleanup
};
