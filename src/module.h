#pragma once

#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

// Module interface: each chat app implements these functions
typedef struct ChatModule {
    const char* name;           // Module identifier (e.g. "wechat", "qq_old", "qq_nt")
    const char* display_name;   // Human-readable name

    int key_size;               // Actual encryption key size in bytes
    int probe_size;             // Bytes to extract from dump at each scan position
    int page_size;              // Database page size for verification
    int progress_interval;      // Log progress every N positions

    // Quick pre-filter: return false to skip this position early.
    // Called for every byte position in the memory dump.
    bool (*filter)(const uint8_t* data);

    // Extract the actual key from probe data.
    // probe: probe_size bytes from dump; key_out: key_size bytes output.
    void (*extract_key)(const uint8_t* probe, uint8_t* key_out);

    // Verify whether a candidate key is correct.
    // key: key_size bytes; page_data: first page of encrypted DB; page_size: size of page_data.
    // Returns true if the key successfully decrypts/verifies the page.
    bool (*verify)(const uint8_t* key, const uint8_t* page_data, int page_size);

    // Decrypt the entire database.
    // key: key_size bytes; input_path: encrypted DB path; output_path: decrypted DB path.
    bool (*decrypt)(const uint8_t* key, const char* input_path, const char* output_path);

    // Print the key in human-readable format to stdout.
    void (*print_key)(const uint8_t* key);

    // Optional: initialize module with database path before scanning.
    // Called once before verify/decrypt. db_path is the ORIGINAL encrypted DB.
    void (*init)(const char* db_path);

    // Optional: cleanup after scanning.
    void (*cleanup)(void);
} ChatModule;

#ifdef __cplusplus
}
#endif
