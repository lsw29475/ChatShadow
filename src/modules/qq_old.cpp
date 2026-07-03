#include "qq_old.h"
#include "../common.h"

#include <cstdio>
#include <cstring>

#define QQ_OLD_KEY_SIZE      16
#define QQ_OLD_PROBE_SIZE    272
#define QQ_OLD_PAGE_SIZE     8192
#define QQ_OLD_PROGRESS_INTERVAL 10000

// TEA implementation (XXTEA decrypt, n is negative for decrypt)
#define DELTA 0x9e3779b9
#define MX (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z)))

static void tea_decrypt(int* v, int n, const int key[4]) {
    unsigned int y, z, sum;
    unsigned p, rounds, e;

    n = -n;  // negative means decrypt
    rounds = 6 + 52 / n;
    sum = rounds * DELTA;
    y = v[0];
    do {
        e = (sum >> 2) & 3;
        for (p = n - 1; p > 0; p--) {
            z = v[p - 1];
            y = v[p] -= MX;
        }
        z = v[n - 1];
        y = v[0] -= MX;
        sum -= DELTA;
    } while (--rounds);
}

static bool qq_old_filter(const uint8_t* data) {
    // Check first and last 4-byte integers don't sum to zero
    int first = *(const int*)data;
    int last = *(const int*)(data + 63 * 4);  // 63 * 4 = 252
    if (first + last == 0)
        return false;
    return true;
}

static void qq_old_extract_key(const uint8_t* probe, uint8_t* key_out) {
    // Deobfuscate: Key[i] = probe[i * 0x11 + (probe[i * 0x11 + 0x10] & 0xF)]
    for (int i = 0; i < QQ_OLD_KEY_SIZE; i++) {
        int offset = i * 0x11;
        int selector = probe[offset + 0x10] & 0xF;
        key_out[i] = probe[offset + selector];
    }
}

static bool qq_old_verify(const uint8_t* key, const uint8_t* page_data, int page_size) {
    if (page_size < 16) return false;

    // Copy page data for decryption (TEA decrypts in-place)
    uint8_t* buf = (uint8_t*)malloc(page_size);
    if (!buf) return false;
    memcpy(buf, page_data, page_size);

    // TEA decrypt with 16-byte key
    tea_decrypt((int*)buf, -(page_size / 4), (const int*)key);

    // Check for 'SQLi' magic bytes (little-endian 'iLQS' = 0x53514C69)
    bool result = (*(int*)buf == 0x53514C69);  // 'iLQS'
    free(buf);
    return result;
}

static bool qq_old_decrypt(const uint8_t* key, const char* input_path, const char* output_path) {
    FILE* in = fopen(input_path, "rb");
    if (!in) return false;

    // Skip 0x400 byte header
    fseek(in, 0x400, SEEK_SET);

    FILE* out = fopen(output_path, "wb");
    if (!out) { fclose(in); return false; }

    uint8_t buf[QQ_OLD_PAGE_SIZE];
    size_t n;

    while ((n = fread(buf, 1, QQ_OLD_PAGE_SIZE, in)) == QQ_OLD_PAGE_SIZE) {
        tea_decrypt((int*)buf, -(QQ_OLD_PAGE_SIZE / 4), (const int*)key);
        fwrite(buf, 1, QQ_OLD_PAGE_SIZE, out);
    }

    fclose(in);
    fclose(out);
    return true;
}

static void qq_old_print_key(const uint8_t* key) {
    for (int i = 0; i < QQ_OLD_KEY_SIZE; i++)
        printf("%02X ", key[i]);
}

const ChatModule qq_old_module = {
    "qq_old",
    "QQ (Legacy)",
    QQ_OLD_KEY_SIZE,
    QQ_OLD_PROBE_SIZE,
    QQ_OLD_PAGE_SIZE,
    QQ_OLD_PROGRESS_INTERVAL,
    qq_old_filter,
    qq_old_extract_key,
    qq_old_verify,
    qq_old_decrypt,
    qq_old_print_key,
    nullptr,  // init
    nullptr   // cleanup
};
