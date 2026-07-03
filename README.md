# ChatShadow v2.0

Cross-platform chat database decryption tool. Extracts encryption keys from process memory dumps to decrypt WeChat and QQ chat history databases.

## Supported Applications

| Module    | App              | Encryption                           | Key Format         |
|-----------|------------------|--------------------------------------|--------------------|
| `wechat`  | WeChat (Windows) | AES-256-CBC + PBKDF2-HMAC-SHA1 (64K) | 32 bytes binary    |
| `qq_old`  | QQ Legacy (PCQQ) | TEA (custom)                         | 16 bytes binary    |
| `qq_nt`   | QQ NT (2023+)    | SQLCipher AES-256-CBC + PBKDF2-SHA512 | 32 chars ASCII     |

## Building

Requirements: CMake 3.14+, C++17 compiler, OpenSSL development libraries.

```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
```

## Usage

```bash
# New task
./chatshadow -M memory.dmp -D Msg.db -A qq_nt -T ./task -N 8

# Resume interrupted task
./chatshadow -R -T ./task

# List supported apps
./chatshadow -L
```

| Flag | Description                          |
|------|--------------------------------------|
| `-M` | Path to memory dump file (.dmp)      |
| `-D` | Path to encrypted database           |
| `-A` | Application: `wechat`, `qq_old`, `qq_nt` |
| `-T` | Task directory for output/progress   |
| `-N` | Thread count (default: auto)         |
| `-R` | Resume from task directory           |
| `-L` | List supported applications          |

## How It Works

1. Loads the memory dump and encrypted database into memory
2. Divides the dump into N slices for parallel scanning
3. Each thread scans byte-by-byte: pre-filter → extract candidate key → verify against DB page
4. On match: saves the key, then decrypts the full database

## Architecture

```
src/
  main.cpp          CLI entry point, task orchestration
  common.h/cpp      Cross-platform utilities (file I/O, paths, etc.)
  scanner.h/cpp     Multi-threaded memory scanning engine
  module.h          Chat module interface (C-style vtable)
  modules/
    wechat.cpp      WeChat AES-256-CBC module
    qq_old.cpp      Legacy QQ TEA module
    qq_nt.cpp       NTQQ SQLCipher module
```

## Adding New Modules

Implement the `ChatModule` interface from `src/module.h`:

```c
typedef struct ChatModule {
    const char* name;
    const char* display_name;
    int key_size, probe_size, page_size, progress_interval;
    bool (*filter)(const uint8_t*);
    void (*extract_key)(const uint8_t*, uint8_t*);
    bool (*verify)(const uint8_t*, const uint8_t*, int);
    bool (*decrypt)(const uint8_t*, const char*, const char*);
    void (*print_key)(const uint8_t*);
} ChatModule;
```

Register in `main.cpp`'s `g_modules[]` array.

## License

MIT. For educational and forensic research purposes only.
