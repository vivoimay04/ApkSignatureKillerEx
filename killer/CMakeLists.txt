cmake_minimum_required(VERSION 3.4.1)
project(SignatureKiller LANGUAGES C CXX ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -fvisibility=hidden")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -fvisibility=hidden")

# ── Dobby: built as a static library (handles its own include paths) ──
set(DOBBY_BUILD_EXAMPLE OFF CACHE BOOL "" FORCE)
set(DOBBY_BUILD_TEST OFF CACHE BOOL "" FORCE)
set(Plugin.SymbolResolver ON CACHE BOOL "" FORCE)
add_subdirectory(src/main/c/dobby dobby_build)

add_library(SignatureKiller SHARED
    src/main/c/mt_jni.c
    src/main/c/dobby_hook.c
    src/main/c/xhook.c
    src/main/c/xh_core.c
    src/main/c/xh_elf.c
    src/main/c/xh_log.c
    src/main/c/xh_util.c
    src/main/c/xh_version.c)

target_include_directories(SignatureKiller PRIVATE
    src/main/c/dobby/include)

find_library(log-lib log)
find_library(dl-lib dl)

target_link_libraries(SignatureKiller
    ${log-lib}
    ${dl-lib}
    dobby_static)
