cmake_minimum_required(VERSION 3.4.1)

# Dobby inline hook (built as a static library)
set(DOBBY_BUILD_EXAMPLE OFF CACHE BOOL "" FORCE)
set(DOBBY_BUILD_TEST OFF CACHE BOOL "" FORCE)
set(Plugin.SymbolResolver ON CACHE BOOL "" FORCE)
add_subdirectory(src/main/c/dobby dobby_build)

set(CMAKE_C_FLAGS "-Wall -Wextra -Werror -fvisibility=hidden")

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
    Dobby)
