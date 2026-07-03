#pragma once

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>

// Cross-platform utilities

// Get current time in milliseconds (monotonic clock)
uint64_t get_time_ms();

// Get human-readable timestamp string
std::string get_timestamp();

// Create a directory (recursive)
bool create_directory(const char* path);

// Copy a file
bool copy_file(const char* src, const char* dst);

// Delete a file
bool delete_file(const char* path);

// Delete a directory and all contents
bool delete_directory(const char* path);

// Check if a file exists
bool file_exists(const char* path);

// Get file size. Returns -1 on error.
int64_t get_file_size(const char* path);

// Read entire file into allocated buffer. Caller must free().
// Returns size read, or -1 on error.
int64_t read_file(const char* path, uint8_t** out_data);

// Read first N bytes of a file into buffer. Returns bytes read, or -1 on error.
int read_file_prefix(const char* path, uint8_t* buffer, int max_size);

// Write buffer to file
bool write_file(const char* path, const uint8_t* data, int size);

// Platform-independent path separator
#ifdef _WIN32
#define PATH_SEP '\\'
#else
#define PATH_SEP '/'
#endif

// Join path components
std::string path_join(const std::string& a, const std::string& b);

// SQLite header magic
#define SQLITE_HEADER "SQLite format 3"
#define SQLITE_HEADER_SIZE 16
