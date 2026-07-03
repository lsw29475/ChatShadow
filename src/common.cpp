#include "common.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <chrono>
#include <ctime>
#include <fstream>
#include <sstream>
#include <iomanip>

#ifdef _WIN32
#include <windows.h>
#include <direct.h>
#define mkdir_impl(path) _mkdir(path)
#define stat_impl _stat
#define RMDIR_IMPL _rmdir
#else
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#define mkdir_impl(path) mkdir(path, 0755)
#define stat_impl stat
#define RMDIR_IMPL rmdir
#endif

uint64_t get_time_ms() {
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
}

std::string get_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    std::stringstream ss;
    ss << std::put_time(std::localtime(&t), "%H:%M:%S");
    ss << "." << std::setfill('0') << std::setw(3) << ms.count();
    return ss.str();
}

bool create_directory(const char* path) {
    std::string p(path);
    for (size_t i = 1; i < p.size(); i++) {
        if (p[i] == '/' || p[i] == '\\') {
            p[i] = '\0';
            mkdir_impl(p.c_str());
            p[i] = '/';
        }
    }
    return mkdir_impl(p.c_str()) == 0 || errno == EEXIST;
}

bool copy_file(const char* src, const char* dst) {
    std::ifstream in(src, std::ios::binary);
    if (!in) return false;
    std::ofstream out(dst, std::ios::binary);
    if (!out) return false;
    out << in.rdbuf();
    return out.good();
}

bool delete_file(const char* path) {
    return std::remove(path) == 0;
}

bool delete_directory(const char* path) {
#ifdef _WIN32
    // Windows recursive delete
    std::string pattern = std::string(path) + "\\*";
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(pattern.c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) return false;
    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
            continue;
        std::string full = std::string(path) + "\\" + fd.cFileName;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            delete_directory(full.c_str());
        else
            DeleteFileA(full.c_str());
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);
    return RemoveDirectoryA(path);
#else
    DIR* dir = opendir(path);
    if (!dir) return false;
    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        std::string full = std::string(path) + "/" + entry->d_name;
        struct stat st;
        if (stat(full.c_str(), &st) == 0) {
            if (S_ISDIR(st.st_mode))
                delete_directory(full.c_str());
            else
                std::remove(full.c_str());
        }
    }
    closedir(dir);
    return rmdir(path) == 0;
#endif
}

bool file_exists(const char* path) {
    struct stat_impl st;
    return stat_impl(path, &st) == 0;
}

int64_t get_file_size(const char* path) {
    struct stat_impl st;
    if (stat_impl(path, &st) != 0) return -1;
    return st.st_size;
}

int64_t read_file(const char* path, uint8_t** out_data) {
    int64_t size = get_file_size(path);
    if (size < 0) return -1;
    *out_data = (uint8_t*)malloc(size);
    if (!*out_data) return -1;
    std::ifstream in(path, std::ios::binary);
    if (!in) { free(*out_data); return -1; }
    in.read((char*)*out_data, size);
    return in.gcount();
}

int read_file_prefix(const char* path, uint8_t* buffer, int max_size) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return -1;
    in.read((char*)buffer, max_size);
    return in.gcount();
}

bool write_file(const char* path, const uint8_t* data, int size) {
    std::ofstream out(path, std::ios::binary);
    if (!out) return false;
    out.write((const char*)data, size);
    return out.good();
}

std::string path_join(const std::string& a, const std::string& b) {
    if (a.empty()) return b;
    if (b.empty()) return a;
    char last = a.back();
    if (last == '/' || last == '\\')
        return a + b;
    return a + PATH_SEP + b;
}
