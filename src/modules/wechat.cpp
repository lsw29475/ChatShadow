#include "wechat.h"
#include "../common.h"

#include <cstdio>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#define WECHAT_KEY_SIZE      32
#define WECHAT_PROBE_SIZE    32
#define WECHAT_PAGE_SIZE     4096
#define WECHAT_SALT_SIZE     16
#define WECHAT_ITER          64000
#define WECHAT_PAGE_RESERVED 32
#define WECHAT_IV_SIZE       16
#define WECHAT_PROGRESS_INTERVAL 1000

// Filter: skip positions where first 3 bytes are identical
// or any byte appears more than 2 times
static bool wechat_filter(const uint8_t* data) {
    // Check consecutive identical bytes at start
    if (data[0] == data[1] && data[1] == data[2])
        return false;

    // Check byte frequency in 32-byte window
    int counts[256] = {0};
    for (int i = 0; i < WECHAT_PROBE_SIZE; i++) {
        if (++counts[data[i]] > 2)
            return false;
    }
    return true;
}

static void wechat_extract_key(const uint8_t* probe, uint8_t* key_out) {
    memcpy(key_out, probe, WECHAT_KEY_SIZE);
}

static bool wechat_verify(const uint8_t* key, const uint8_t* page_data, int page_size) {
    if (page_size < WECHAT_PAGE_SIZE) return false;

    uint8_t dec_key[32] = {0};
    uint8_t mac_key[32] = {0};
    uint8_t mac_salt[WECHAT_SALT_SIZE] = {0};
    uint8_t hash_key[32] = {0};
    unsigned int nPage = 1;

    // Derive decryption key: PBKDF2-HMAC-SHA1(key, salt, 64000)
    PKCS5_PBKDF2_HMAC_SHA1((const char*)key, WECHAT_KEY_SIZE,
                           page_data, WECHAT_SALT_SIZE,
                           WECHAT_ITER, sizeof(dec_key), dec_key);

    // Derive MAC key from decryption key
    for (int i = 0; i < WECHAT_SALT_SIZE; i++)
        mac_salt[i] = page_data[i] ^ 0x3a;

    PKCS5_PBKDF2_HMAC_SHA1((const char*)dec_key, sizeof(dec_key),
                           mac_salt, sizeof(mac_salt),
                           2, sizeof(mac_key), mac_key);

    // HMAC-SHA1 over page data
    unsigned int hash_len = 0;
    HMAC(EVP_sha1(), mac_key, sizeof(mac_key),
         page_data + WECHAT_SALT_SIZE,
         WECHAT_PAGE_SIZE - WECHAT_PAGE_RESERVED - WECHAT_SALT_SIZE,
         hash_key, &hash_len);

    // Also include page number in the HMAC
    HMAC(EVP_sha1(), mac_key, sizeof(mac_key),
         (const uint8_t*)&nPage, sizeof(nPage),
         hash_key, &hash_len);

    // Compare with stored hash at end of page
    return memcmp(hash_key, page_data + WECHAT_PAGE_SIZE - WECHAT_PAGE_RESERVED,
                  hash_len) == 0;
}

static bool wechat_decrypt(const uint8_t* key, const char* input_path, const char* output_path) {
    // Read first page to get salt
    uint8_t page_data[WECHAT_PAGE_SIZE];
    int n = read_file_prefix(input_path, page_data, WECHAT_PAGE_SIZE);
    if (n != WECHAT_PAGE_SIZE) return false;

    // Derive decryption key
    uint8_t dec_key[32] = {0};
    PKCS5_PBKDF2_HMAC_SHA1((const char*)key, WECHAT_KEY_SIZE,
                           page_data, WECHAT_SALT_SIZE,
                           WECHAT_ITER, sizeof(dec_key), dec_key);

    // Open input and output
    FILE* in = fopen(input_path, "rb");
    if (!in) return false;
    FILE* out = fopen(output_path, "wb");
    if (!out) { fclose(in); return false; }

    uint8_t buf[WECHAT_PAGE_SIZE];
    uint8_t dec_buf[WECHAT_PAGE_SIZE];
    int page_num = 0;

    while (fread(buf, 1, WECHAT_PAGE_SIZE, in) == WECHAT_PAGE_SIZE) {
        if (page_num == 0) {
            // First page: write SQLite header
            memcpy(dec_buf, SQLITE_HEADER, SQLITE_HEADER_SIZE);
        }

        // IV is before the reserved area at end of page
        const uint8_t* iv = buf + WECHAT_PAGE_SIZE - WECHAT_PAGE_RESERVED - WECHAT_IV_SIZE;

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, dec_key, iv);
        EVP_CIPHER_CTX_set_padding(ctx, 0);

        int fix_offset = (page_num == 0) ? WECHAT_SALT_SIZE : 0;
        int out_len = 0, final_len = 0;
        int data_len = WECHAT_PAGE_SIZE - WECHAT_PAGE_RESERVED - WECHAT_IV_SIZE - fix_offset;

        EVP_DecryptUpdate(ctx, dec_buf + fix_offset, &out_len,
                         buf + fix_offset, data_len);
        EVP_DecryptFinal_ex(ctx, dec_buf + fix_offset + out_len, &final_len);
        EVP_CIPHER_CTX_free(ctx);

        fwrite(dec_buf, 1, WECHAT_PAGE_SIZE, out);
        page_num++;
    }

    fclose(in);
    fclose(out);
    return true;
}

static void wechat_print_key(const uint8_t* key) {
    for (int i = 0; i < WECHAT_KEY_SIZE; i++)
        printf("%02X ", key[i]);
}

const ChatModule wechat_module = {
    "wechat",
    "WeChat",
    WECHAT_KEY_SIZE,
    WECHAT_PROBE_SIZE,
    WECHAT_PAGE_SIZE,
    WECHAT_PROGRESS_INTERVAL,
    wechat_filter,
    wechat_extract_key,
    wechat_verify,
    wechat_decrypt,
    wechat_print_key,
    nullptr,  // init
    nullptr,  // cleanup
    nullptr,
};
