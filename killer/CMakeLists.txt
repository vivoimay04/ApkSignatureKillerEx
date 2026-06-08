cmake_minimum_required(VERSION 3.4.1)
project(SignatureKiller)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -fvisibility=hidden")

add_library(SignatureKiller SHARED
    src/main/c/mt_jni.c
    src/main/c/inline_hook.c
    src/main/c/xhook.c
    src/main/c/xh_core.c
    src/main/c/xh_elf.c
    src/main/c/xh_log.c
    src/main/c/xh_util.c
    src/main/c/xh_version.c)

find_library(log-lib log)
find_library(dl-lib dl)

target_link_libraries(SignatureKiller
    ${log-lib}
    ${dl-lib})
