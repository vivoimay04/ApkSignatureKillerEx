cmake_minimum_required(VERSION 3.4.1)
project(SignatureKiller LANGUAGES C CXX ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -fvisibility=hidden")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -fvisibility=hidden")

# ── Dobby source dir ──
set(DOBBY src/main/c/dobby)

# ── Collect all Dobby source files ──
file(GLOB_RECURSE DOBBY_SOURCES
    ${DOBBY}/source/*.c ${DOBBY}/source/*.cc ${DOBBY}/source/*.cpp ${DOBBY}/source/*.S
    ${DOBBY}/builtin-plugin/*.c ${DOBBY}/builtin-plugin/*.cc ${DOBBY}/builtin-plugin/*.cpp)

# ── Filter out non-Android files ──
foreach(F ${DOBBY_SOURCES})
    set(KEEP TRUE)
    # Exclude platform-specific: windows, darwin (macOS), kernel-mode, test, example
    foreach(E "windows" "darwin" "macho" "/pe/" "KernelMode" "test" "example"
            "deprecated" "ApplicationEventMonitor" "SupervisorCallMonitor")
        if(F MATCHES ".*${E}.*")
            set(KEEP FALSE)
        endif()
    endforeach()
    # Exclude dummy/template files
    foreach(E "clear-cache-tool-arm-dummy" "clear-cache-tool-arm64-dummy" "closure-bridge-template-arm")
        if(F MATCHES ".*${E}.*")
            set(KEEP FALSE)
        endif()
    endforeach()
    if(KEEP)
        list(APPEND FILTERED ${F})
    endif()
endforeach()

message(STATUS "Dobby source files: ${FILTERED}")

# ── Dobby include paths (mirroring Dobby's own CMakeLists.txt) ──
set(DOBBY_INCLUDES
    ${DOBBY}                              # .
    ${DOBBY}/include                      # ./include
    ${DOBBY}/source                       # ./source
    ${DOBBY}/source/dobby                 # source/dobby
    ${DOBBY}/external                     # ./external
    ${DOBBY}/external/logging             # ./external/logging
    ${DOBBY}/builtin-plugin               # ./builtin-plugin
    ${DOBBY}/builtin-plugin/SymbolResolver
    ${DOBBY}/source/Backend/UserMode      # for MultiThreadSupport etc.
)

add_library(SignatureKiller SHARED
    src/main/c/mt_jni.c
    src/main/c/dobby_hook.c
    src/main/c/xhook.c
    src/main/c/xh_core.c
    src/main/c/xh_elf.c
    src/main/c/xh_log.c
    src/main/c/xh_util.c
    src/main/c/xh_version.c
    ${FILTERED})

target_include_directories(SignatureKiller PRIVATE ${DOBBY_INCLUDES})

find_library(log-lib log)
find_library(dl-lib dl)

target_link_libraries(SignatureKiller
    ${log-lib}
    ${dl-lib})
