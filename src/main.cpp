#include "common.h"
#include "scanner.h"
#include "module.h"

#include "modules/wechat.h"
#include "modules/wechat_v4_bin.h"
#include "modules/qq_old.h"
#include "modules/qq_nt.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <vector>

// Forward declaration
static bool run_crack(const char* mem_path, const char* db_path, const char* task_dir,
                      const ChatModule* module, int thread_count, bool resume);

// All registered modules
static const ChatModule* g_modules[] = {
    &wechat_module,
    &wechat_v4_bin_module,
    &qq_old_module,
    &qq_nt_module,
};
static const int g_module_count = sizeof(g_modules) / sizeof(g_modules[0]);

static const ChatModule* find_module(const char* name) {
    for (int i = 0; i < g_module_count; i++) {
        if (strcmp(g_modules[i]->name, name) == 0)
            return g_modules[i];
    }
    return nullptr;
}

static void print_usage(const char* prog) {
    printf("ChatShadow - Chat Database Decryption Tool\n");
    printf("Usage:\n");
    printf("  %s -M <memory.dmp> -D <msg.db> -A <app> -T <task_dir> [-N <threads>]\n", prog);
    printf("  %s -R -T <task_dir>    (resume previous task)\n\n", prog);
    printf("Options:\n");
    printf("  -M <path>    Memory dump file\n");
    printf("  -D <path>    Encrypted database file\n");
    printf("  -A <app>     Application type: ");
    for (int i = 0; i < g_module_count; i++) {
        printf("%s%s", i > 0 ? ", " : "", g_modules[i]->name);
    }
    printf("\n");
    printf("  -T <path>    Task directory\n");
    printf("  -N <num>     Number of threads (default: auto)\n");
    printf("  -R           Resume from task directory\n");
    printf("  -L           List supported applications\n");
}

// Progress callback for scanner
static void progress_cb(int thread_id, int64_t pos, int64_t total,
                        double percent, uint64_t elapsed) {
    printf("%s---Thread %d: pos: 0x%llx/0x%llx  Progress %.2f%%  Time: %llu s\n",
           get_timestamp().c_str(), thread_id,
           (unsigned long long)pos, (unsigned long long)total,
           percent, (unsigned long long)elapsed);
}

// Create a new cracking task
static bool create_task(const char* mem_path, const char* db_path,
                        const char* task_dir, const ChatModule* module,
                        int thread_count) {
    printf("=== ChatShadow: Creating new task ===\n");
    printf("Module:     %s (%s)\n", module->name, module->display_name);
    printf("Memory:     %s\n", mem_path);
    printf("Database:   %s\n", db_path);
    printf("Task dir:   %s\n", task_dir);
    printf("Threads:    %d\n", thread_count);

    // Create task directory
    if (file_exists(task_dir)) {
        printf("Removing existing task directory...\n");
        delete_directory(task_dir);
    }
    if (!create_directory(task_dir)) {
        fprintf(stderr, "Error: Cannot create task directory: %s\n", task_dir);
        return false;
    }

    // Copy memory dump
    std::string mem_dest = path_join(task_dir, "TaskMem.dmp");
    printf("Copying memory dump...\n");
    if (!copy_file(mem_path, mem_dest.c_str())) {
        fprintf(stderr, "Error: Cannot copy memory dump\n");
        return false;
    }

    // Copy database
    std::string db_dest = path_join(task_dir, "TaskDB.db");
    printf("Copying database...\n");
    if (!copy_file(db_path, db_dest.c_str())) {
        fprintf(stderr, "Error: Cannot copy database\n");
        return false;
    }

    return run_crack(mem_dest.c_str(), db_dest.c_str(), task_dir, module, thread_count, false);
}

// Resume an existing task
static bool resume_task(const char* task_dir) {
    printf("=== ChatShadow: Resuming task ===\n");

    std::string mem_path = path_join(task_dir, "TaskMem.dmp");
    std::string db_path = path_join(task_dir, "TaskDB.db");
    std::string status_path = path_join(task_dir, "Status.json");

    if (!file_exists(mem_path.c_str())) {
        fprintf(stderr, "Error: Memory dump not found: %s\n", mem_path.c_str());
        return false;
    }
    if (!file_exists(db_path.c_str())) {
        fprintf(stderr, "Error: Database not found: %s\n", db_path.c_str());
        return false;
    }
    if (!file_exists(status_path.c_str())) {
        fprintf(stderr, "Error: Status file not found: %s\n", status_path.c_str());
        return false;
    }

    // Read module name and thread count from status
    const char* module_name = nullptr;
    uint64_t dummy;
    restore_scan_progress(task_dir, 1, &dummy, &module_name);
    int thread_count = restore_thread_count(task_dir);

    if (!module_name) {
        fprintf(stderr, "Error: Cannot determine module from status file\n");
        return false;
    }

    const ChatModule* module = find_module(module_name);
    if (!module) {
        fprintf(stderr, "Error: Unknown module '%s'\n", module_name);
        return false;
    }

    printf("Module:     %s (%s)\n", module->name, module->display_name);
    printf("Threads:    %d\n", thread_count);

    return run_crack(mem_path.c_str(), db_path.c_str(), task_dir, module, thread_count, true);
}

// Run the cracking process
bool run_crack(const char* mem_path, const char* db_path, const char* task_dir,
               const ChatModule* module, int thread_count, bool resume) {
    // Determine thread count
    if (thread_count <= 0) {
        thread_count = (int)std::thread::hardware_concurrency();
        if (thread_count < 1) thread_count = 4;
    }

    // Read database first page for verification
    uint8_t* page_data = (uint8_t*)malloc(module->page_size);
    if (!page_data) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        return false;
    }

    // For NTQQ, skip the 1024-byte header before reading SQLCipher page
    if (strcmp(module->name, "qq_nt") == 0) {
        FILE* f = fopen(db_path, "rb");
        if (!f) {
            fprintf(stderr, "Error: Cannot open database: %s\n", db_path);
            free(page_data);
            return false;
        }
        fseek(f, 1024, SEEK_SET);  // Skip QQ header
        size_t n = fread(page_data, 1, module->page_size, f);
        fclose(f);
        if (n != (size_t)module->page_size) {
            fprintf(stderr, "Error: Cannot read database page (got %zu bytes)\n", n);
            free(page_data);
            return false;
        }
    } else {
        int n = read_file_prefix(db_path, page_data, module->page_size);
        if (n != module->page_size) {
            fprintf(stderr, "Error: Cannot read database page (got %d bytes)\n", n);
            free(page_data);
            return false;
        }
    }

    // Memory-map the dump file
    int64_t dump_size;
    uint8_t* dump_data;
    dump_size = read_file(mem_path, &dump_data);
    if (dump_size < 0 || !dump_data) {
        fprintf(stderr, "Error: Cannot read memory dump: %s\n", mem_path);
        free(page_data);
        return false;
    }

    printf("Memory dump loaded: %lld bytes (%.2f MB)\n",
           (long long)dump_size, dump_size / (1024.0 * 1024.0));

    // For NTQQ, pre-create the clean DB for fast verification
    if (module->init) {
        module->init(db_path);
    }

    // YARA-style pre-scan: if module supports it, find candidates via pattern matching
    ScanResult result;
    memset(&result, 0, sizeof(result));
    std::string password_path = path_join(task_dir, "Password");
    std::string dec_db_path = path_join(task_dir, "DecDB.db");

    if (module->scan_candidates) {
        const int max_candidates = 1024;
        uint8_t* key_buf = (uint8_t*)malloc(max_candidates * module->key_size);
        int n = module->scan_candidates(dump_data, dump_size, key_buf, max_candidates);
        printf("YARA pre-scan: %d candidates found\n", n);

        for (int i = 0; i < n; i++) {
            uint8_t* key = key_buf + i * module->key_size;
            if (module->verify(key, page_data, module->page_size)) {
                printf("\n  KEY FOUND via YARA scan (candidate %d/%d)\n", i+1, n);
                printf("  Key: ");
                module->print_key(key);
                printf("\n");
                result.found = true;
                memcpy(result.key, key, module->key_size);
                break;
            }
        }
        free(key_buf);
    }

    if (!result.found) {
        // Configure and run byte-by-byte scan
        ScanConfig config;
        memset(&config, 0, sizeof(config));
        config.dump_data = dump_data;
        config.dump_size = dump_size;
        config.thread_count = thread_count;
        config.module = module;
        config.page_data = page_data;
        config.page_size = module->page_size;
        config.password_path = password_path.c_str();
        config.task_dir = task_dir;
        config.resume = resume;

        result = run_scan(config, progress_cb);
    }

    free(dump_data);
    free(page_data);

    if (!result.found) {
        printf("\nKey not found in memory dump.\n");
        return false;
    }

    printf("\n=== Key found! Decrypting database... ===\n");

    // Decrypt full database
    if (module->decrypt(result.key, db_path, dec_db_path.c_str())) {
        printf("Database decrypted: %s\n", dec_db_path.c_str());
    } else {
        fprintf(stderr, "Warning: Full database decryption failed.\n");
        fprintf(stderr, "The key was found but decryption may need external tools.\n");
    }

    return true;
}

int main(int argc, char** argv) {
    // Disable stdio buffering for real-time progress output
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    const char* mem_path = nullptr;
    const char* db_path = nullptr;
    const char* task_dir = nullptr;
    const char* app_name = nullptr;
    int thread_count = 0;
    bool resume = false;

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-M") == 0 && i + 1 < argc) {
            mem_path = argv[++i];
        } else if (strcmp(argv[i], "-D") == 0 && i + 1 < argc) {
            db_path = argv[++i];
        } else if (strcmp(argv[i], "-T") == 0 && i + 1 < argc) {
            task_dir = argv[++i];
        } else if (strcmp(argv[i], "-A") == 0 && i + 1 < argc) {
            app_name = argv[++i];
        } else if (strcmp(argv[i], "-N") == 0 && i + 1 < argc) {
            thread_count = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-R") == 0) {
            resume = true;
        } else if (strcmp(argv[i], "-L") == 0) {
            printf("Supported applications:\n");
            for (int j = 0; j < g_module_count; j++) {
                printf("  %-10s %s\n", g_modules[j]->name, g_modules[j]->display_name);
            }
            return 0;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }

    // Resume mode
    if (resume) {
        if (!task_dir) {
            fprintf(stderr, "Error: -T <task_dir> required for resume\n");
            return 1;
        }
        return resume_task(task_dir) ? 0 : 1;
    }

    // New task mode
    if (!mem_path || !db_path || !app_name || !task_dir) {
        print_usage(argv[0]);
        return 1;
    }

    const ChatModule* module = find_module(app_name);
    if (!module) {
        fprintf(stderr, "Error: Unknown application '%s'\n", app_name);
        fprintf(stderr, "Use -L to list supported applications.\n");
        return 1;
    }

    return create_task(mem_path, db_path, task_dir, module, thread_count) ? 0 : 1;
}
