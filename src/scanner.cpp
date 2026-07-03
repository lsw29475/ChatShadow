#include "scanner.h"
#include "common.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <mutex>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

struct ThreadContext {
    int id;
    const ScanConfig* config;
    std::atomic<bool>* stop_flag;
    ProgressCallback progress_cb;

    bool found;
    int64_t position;
};

static void scanning_thread(ThreadContext* ctx) {
    const ScanConfig* cfg = ctx->config;
    const ChatModule* mod = cfg->module;

    // Fixed slice: each thread gets an independent memory region
    // This avoids cache-line contention between threads
    int64_t slice_size = cfg->dump_size / cfg->thread_count;
    int64_t start = (ctx->id - 1) * slice_size;
    int64_t end = (ctx->id == cfg->thread_count) ? cfg->dump_size : start + slice_size;
    int64_t dump_limit = end - mod->probe_size;

    uint8_t* key = (uint8_t*)malloc(mod->key_size);
    int64_t pos = start;

    // Resume support
    uint64_t prev_elapsed = 0;
    if (cfg->resume) {
        const char* module_name;
        pos = restore_scan_progress(cfg->task_dir, ctx->id, &prev_elapsed, &module_name);
        if (pos < start || pos >= end) pos = start;
    }

    uint64_t start_time = get_time_ms();
    int counter = 0;

    for (; pos < dump_limit; pos++) {
        if (ctx->stop_flag->load(std::memory_order_relaxed)) break;

        // --- Page-level dead-zone skip ---
        if (cfg->dump_data[pos] == 0x00) {
            bool all_zero = true;
            for (int z = 1; z < 64 && pos + z < dump_limit; z++) {
                if (cfg->dump_data[pos + z] != 0x00) { all_zero = false; break; }
            }
            if (all_zero) {
                int64_t skip_to = ((pos >> 12) + 1) << 12;
                if (skip_to > pos + 64 && skip_to < dump_limit) {
                    pos = skip_to - 1;
                    continue;
                }
            }
        }
        {
            uint8_t first = cfg->dump_data[pos];
            if (first != 0x00) {
                bool all_same = true;
                for (int z = 1; z < 32 && pos + z < dump_limit; z++) {
                    if (cfg->dump_data[pos + z] != first) { all_same = false; break; }
                }
                if (all_same) {
                    int64_t skip_to = ((pos >> 12) + 1) << 12;
                    if (skip_to > pos + 32 && skip_to < dump_limit) {
                        pos = skip_to - 1;
                        continue;
                    }
                }
            }
        }

        // Multi-layer filter
        if (!mod->filter(cfg->dump_data + pos)) continue;

        // Extract and verify
        mod->extract_key(cfg->dump_data + pos, key);
        if (mod->verify(key, cfg->page_data, cfg->page_size)) {
            ctx->found = true;
            ctx->position = pos;
            ctx->stop_flag->store(true);
            printf("\nThread %d: KEY FOUND at 0x%llx\n", ctx->id, (unsigned long long)pos);
            printf("Key: ");
            mod->print_key(key);
            printf("\n");
            write_file(cfg->password_path, key, mod->key_size);
            break;
        }

        // Progress reporting
        if (counter++ % mod->progress_interval == 0) {
            uint64_t elapsed = (get_time_ms() - start_time) / 1000 + prev_elapsed;
            double pct = (double)(pos - start) / (end - start) * 100.0;
            int64_t remaining = pct > 0 ? (int64_t)((100.0 - pct) * elapsed / pct) : 0;

            printf("%s  T%d [%5.1f%%]  ETA %lldm%llds\n",
                   get_timestamp().c_str(), ctx->id, pct,
                   (long long)(remaining / 60), (long long)(remaining % 60));

            save_scan_progress(cfg->task_dir, cfg->thread_count, ctx->id,
                              pos, cfg->dump_size, elapsed, mod->name);
        }
    }

    free(key);
}

ScanResult run_scan(const ScanConfig& config, ProgressCallback progress_cb) {
    ScanResult result;
    memset(&result, 0, sizeof(result));

    if (!config.dump_data || config.dump_size <= 0) return result;
    if (!config.module) return result;
    if (config.thread_count < 1) return result;

    int thread_count = config.thread_count;
    if (config.dump_size / thread_count < 1024 * 1024) {
        thread_count = (int)(config.dump_size / (1024 * 1024));
        if (thread_count < 1) thread_count = 1;
    }

    printf("Starting scan with %d threads (fixed-slice mode)\n", thread_count);
    printf("Module: %s (%s)  Dump: %.0f MB  Key: %d bytes\n",
           config.module->name, config.module->display_name,
           config.dump_size / (1024.0 * 1024.0), config.module->key_size);

    uint64_t start_time = get_time_ms();
    std::atomic<bool> stop_flag(false);

    std::vector<std::thread> threads;
    std::vector<ThreadContext> contexts(thread_count);

    for (int i = 0; i < thread_count; i++) {
        contexts[i].id = i + 1;
        contexts[i].config = &config;
        contexts[i].stop_flag = &stop_flag;
        contexts[i].progress_cb = progress_cb;
        contexts[i].found = false;
        contexts[i].position = -1;
    }

    for (int i = 0; i < thread_count; i++)
        threads.emplace_back(scanning_thread, &contexts[i]);

    for (auto& t : threads) t.join();

    result.elapsed_ms = get_time_ms() - start_time;

    for (int i = 0; i < thread_count; i++) {
        if (contexts[i].found) {
            result.found = true;
            result.thread_id = contexts[i].id;
            result.position = contexts[i].position;
            result.key_size = config.module->key_size;
            uint8_t* key_data = NULL;
            int64_t n = read_file(config.password_path, &key_data);
            if (n > 0 && n <= (int)sizeof(result.key)) {
                memcpy(result.key, key_data, n);
                result.key_size = (int)n;
            }
            free(key_data);
            break;
        }
    }

    if (!result.found)
        printf("Scan complete. Key not found.\n");

    printf("Total time: %.2f seconds\n", result.elapsed_ms / 1000.0);
    return result;
}

void save_scan_progress(const char* task_dir, int thread_count, int thread_id,
                        int64_t pos, int64_t total_size, uint64_t elapsed_sec,
                        const char* module_name) {
    static std::mutex g_mutex;
    std::lock_guard<std::mutex> lock(g_mutex);

    std::string status_path = path_join(task_dir, "Status.json");
    json data;
    std::ifstream in(status_path);
    if (in.is_open()) { in >> data; in.close(); }

    data["ThreadNum"] = thread_count;
    data["TaskType"] = module_name;
    data["TotalSize"] = total_size;
    data["Thread" + std::to_string(thread_id)] = pos;
    data["Thread" + std::to_string(thread_id) + "UsedTime"] = elapsed_sec;

    std::ofstream out(status_path);
    if (out.is_open()) out << data.dump(2);
}

int64_t restore_scan_progress(const char* task_dir, int thread_id, uint64_t* out_elapsed,
                              const char** out_module_name) {
    std::string status_path = path_join(task_dir, "Status.json");
    std::ifstream in(status_path);
    if (!in.is_open()) return 0;
    json data; in >> data;
    if (out_module_name && data.contains("TaskType")) {
        static std::string name;
        name = data["TaskType"].get<std::string>();
        *out_module_name = name.c_str();
    }
    if (out_elapsed)
        *out_elapsed = data.value("Thread" + std::to_string(thread_id) + "UsedTime", (uint64_t)0);
    return data.value("Thread" + std::to_string(thread_id), (int64_t)0);
}

int restore_thread_count(const char* task_dir) {
    std::string status_path = path_join(task_dir, "Status.json");
    std::ifstream in(status_path);
    if (!in.is_open()) return 0;
    json data; in >> data;
    return data.value("ThreadNum", 0);
}
