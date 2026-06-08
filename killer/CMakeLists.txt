cmake_minimum_required(VERSION 3.4.1)
project(SignatureKiller LANGUAGES C CXX ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -fvisibility=hidden")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -fvisibility=hidden")

# ── Dobby: collect Android-relevant sources ──
file(GLOB_RECURSE DOBBY_SOURCES
    src/main/c/dobby/source/*.c
    src/main/c/dobby/source/*.cc
    src/main/c/dobby/source/*.cpp
    src/main/c/dobby/source/*.S)

# Compatible foreach+if filter (works with any CMake version)
set(DOBBY_EXCLUDE_REGEX
    "KernelMode|windows|darwin|test|example|lighthouse|macho|deprecated|FunctionWrapper"
    "clear-cache-tool-arm-dummy|clear-cache-tool-arm64-dummy|closure-bridge-template-arm"
)
set(FILTERED_SOURCES "")
foreach(F ${DOBBY_SOURCES})
    set(KEEP TRUE)
    foreach(E ${DOBBY_EXCLUDE_REGEX})
        if(F MATCHES ${E})
            set(KEEP FALSE)
            break()
        endif()
    endforeach()
    if(KEEP)
        list(APPEND FILTERED_SOURCES ${F})
    endif()
endforeach()

add_library(SignatureKiller SHARED
    src/main/c/mt_jni.c
    src/main/c/dobby_hook.c
    src/main/c/xhook.c
    src/main/c/xh_core.c
    src/main/c/xh_elf.c
    src/main/c/xh_log.c
    src/main/c/xh_util.c
    src/main/c/xh_version.c
    ${FILTERED_SOURCES})

target_include_directories(SignatureKiller PRIVATE
    src/main/c/dobby/include)

find_library(log-lib log)
find_library(dl-lib dl)

target_link_libraries(SignatureKiller
    ${log-lib}
    ${dl-lib})
