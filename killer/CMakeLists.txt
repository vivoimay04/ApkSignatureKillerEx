cmake_minimum_required(VERSION 3.4.1)
project(SignatureKiller LANGUAGES C CXX ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror -fvisibility=hidden")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Werror -fvisibility=hidden")

# ── Collect Dobby source files (Android-relevant only) ──
file(GLOB_RECURSE DOBBY_SOURCES
    src/main/c/dobby/source/*.c
    src/main/c/dobby/source/*.cc
    src/main/c/dobby/source/*.cpp
    src/main/c/dobby/source/*.S)

list(FILTER DOBBY_SOURCES EXCLUDE_REGEX
    ".*/(KernelMode|windows|darwin|test|example|deprecated|lighthouse|macho)/.*")
list(FILTER DOBBY_SOURCES EXCLUDE_REGEX
    ".*(clear-cache-tool-arm-dummy|clear-cache-tool-arm64-dummy|closure-bridge-template-arm\\.S).*")

add_library(SignatureKiller SHARED
    src/main/c/mt_jni.c
    src/main/c/dobby_hook.c
    src/main/c/xhook.c
    src/main/c/xh_core.c
    src/main/c/xh_elf.c
    src/main/c/xh_log.c
    src/main/c/xh_util.c
    src/main/c/xh_version.c
    ${DOBBY_SOURCES})

target_include_directories(SignatureKiller PRIVATE
    src/main/c/dobby/include)

find_library(log-lib log)
find_library(dl-lib dl)
find_library(c++-lib c++)

target_link_libraries(SignatureKiller
    ${log-lib}
    ${dl-lib}
    ${c++-lib})
