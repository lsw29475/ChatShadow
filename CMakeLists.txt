cmake_minimum_required(VERSION 3.14)
project(chatshadow VERSION 2.0.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Silence OpenSSL 3.0 deprecation warnings for HMAC_CTX / PKCS5_PBKDF2
add_definitions(-DOPENSSL_SUPPRESS_DEPRECATED)

# Platform detection
if(WIN32)
    add_definitions(-D_WIN32)
    set(PLATFORM_LIBS ws2_32)
else()
    set(PLATFORM_LIBS pthread dl)
endif()

# Find OpenSSL (required for WeChat module and NTQQ verify)
find_package(OpenSSL REQUIRED)

# Threads
find_package(Threads REQUIRED)

# nlohmann/json - try system first, then download
find_package(nlohmann_json QUIET)
if(NOT nlohmann_json_FOUND)
    message(STATUS "nlohmann_json not found, downloading...")
    file(DOWNLOAD
        https://github.com/nlohmann/json/releases/download/v3.11.3/json.hpp
        ${CMAKE_BINARY_DIR}/nlohmann/json.hpp
        STATUS download_status
    )
    list(GET download_status 0 status_code)
    if(NOT status_code EQUAL 0)
        # Create dir and retry
        file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/nlohmann)
        file(DOWNLOAD
            https://github.com/nlohmann/json/releases/download/v3.11.3/json.hpp
            ${CMAKE_BINARY_DIR}/nlohmann/json.hpp
        )
    endif()
    set(NLOHMANN_JSON_INCLUDE_DIR ${CMAKE_BINARY_DIR})
else()
    set(NLOHMANN_JSON_INCLUDE_DIR ${nlohmann_json_INCLUDE_DIRS})
endif()

# Source files
set(SOURCES
    src/main.cpp
    src/common.cpp
    src/scanner.cpp
    src/modules/wechat.cpp
    src/modules/wechat_v4_bin.cpp
    src/modules/qq_old.cpp
    src/modules/qq_nt.cpp
)

# Executable
add_executable(chatshadow ${SOURCES})

target_include_directories(chatshadow PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${NLOHMANN_JSON_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(chatshadow PRIVATE
    OpenSSL::Crypto
    Threads::Threads
    ${PLATFORM_LIBS}
)

# Install
install(TARGETS chatshadow RUNTIME DESTINATION bin)

# Print configuration summary
message(STATUS "=== ChatShadow Configuration ===")
message(STATUS "OpenSSL:   ${OPENSSL_VERSION}")
message(STATUS "JSON:      ${NLOHMANN_JSON_INCLUDE_DIR}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "================================")
