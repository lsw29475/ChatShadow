#pragma once

#include "module.h"
#include <cstdint>
#include <atomic>
#include <thread>
#include <mutex>
#include <vector>
#include <string>

// Scanner configuration for a cracking task
struct ScanConfig {
    uint8_t* dump_data;         // Pointer to entire memory dump in memory
    int64_t dump_size;          // Total size of dump
    int thread_count;           // Number of scanning threads
    const ChatModule* module;   // Module to use for this scan

    uint8_t* page_data;         // First page of encrypted DB for verification
    int page_size;

    const char* password_path;  // Where to save the found key
    const char* task_dir;       // Task directory for status files
    bool resume;                // Whether to resume from previous state
};

// Result of a scan
struct ScanResult {
    bool found;                 // Whether key was found
    int thread_id;              // Which thread found it
    int64_t position;           // Byte position in dump where key was found
    uint8_t key[64];            // The found key (max 64 bytes)
    int key_size;               // Actual key size
    uint64_t elapsed_ms;        // Total time taken
};

// Progress callback type: called periodically with (thread_id, position, total, percent)
typedef void (*ProgressCallback)(int thread_id, int64_t position, int64_t total, double percent, uint64_t elapsed_sec);

// Run a cracking scan with the given config.
// Returns the result. Blocks until complete or key found.
ScanResult run_scan(const ScanConfig& config, ProgressCallback progress_cb = nullptr);

// Save scan progress to status file (called periodically by scanner threads)
void save_scan_progress(const char* task_dir, int thread_count, int thread_id,
                        int64_t pos, int64_t total_size, uint64_t elapsed_sec,
                        const char* module_name);

// Restore scan progress from status file.
// Returns the last position for the given thread, or 0 if not found.
// out_elapsed: previous elapsed time in seconds.
int64_t restore_scan_progress(const char* task_dir, int thread_id, uint64_t* out_elapsed,
                              const char** out_module_name);

// Get thread count from status file
int restore_thread_count(const char* task_dir);
