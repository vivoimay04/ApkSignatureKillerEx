/**
 * ARM64 inline hook for SVC openAt bypass.
 *
 * Two methods to find the openAt function pointer:
 * 1. Try dlsym (works if libtest.so exports JNI symbols - default NDK behavior)
 * 2. Hook RegisterNatives in JNINativeInterface table (works if libtest.so
 *    registers methods via JNI_OnLoad -> RegisterNatives)
 *
 * Once found: overwrite first 16 bytes with LDR X17+BR X17 (absolute jump)
 * to our handler, saving original code in a trampoline.
 */

#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>
#include <pthread.h>
#include <jni.h>
#include <android/log.h>
#include "xh_log.h"

#define LOG_TAG "InlineHook"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

extern const char *apkPath__;
extern const char *repPath__;

// ── Hook status (readable from Java via JNI) ──
static char g_hook_status[256] = "not_attempted";

const char* get_hook_status(void) {
    return g_hook_status;
}

// ── ARM64 absolute jump: LDR X17, [PC, #8]; BR X17; <8-byte target> ──
static void emit_abs_jump(void *where, void *target) {
    uint32_t *code = (uint32_t *)where;
    code[0] = 0x4C000051;  // LDR X17, [PC, #8]
    code[1] = 0xD61F0220;  // BR X17
    memcpy(&code[2], &target, 8);
    __builtin___clear_cache(where, (char *)where + 16);
}

typedef jint (*openAt_jni_t)(JNIEnv *, jclass, jstring);
static openAt_jni_t g_original = NULL;

// ── Our replacement handler ──
static jint my_handler(JNIEnv *env, jclass clazz, jstring path) {
    const char *path_utf = (*env)->GetStringUTFChars(env, path, 0);
    jint result;

    if (apkPath__ && repPath__ && strcmp(path_utf, apkPath__) == 0) {
        LOGI("Redirect openAt(%s) -> %s", path_utf, repPath__);
        jstring repPath = (*env)->NewStringUTF(env, repPath__);
        result = g_original(env, clazz, repPath);
        (*env)->DeleteLocalRef(env, repPath);
    } else {
        result = g_original(env, clazz, path);
    }

    (*env)->ReleaseStringUTFChars(env, path, path_utf);
    return result;
}

// ── Inline hook installer ──
static int g_hook_installed = 0;

static void install_hook_on(void *target) {
    if (g_hook_installed) return;
    LOGI("Installing inline hook at %p", target);

    // First instr for log
    uint32_t first_instr = *(volatile uint32_t *)target;
    LOGI("First instr: 0x%08x", first_instr);

    // Save original 4 instructions
    uint32_t original_code[4];
    memcpy(original_code, target, 16);

    // Allocate trampoline
    long page_size = sysconf(_SC_PAGESIZE);
    void *trampoline = mmap(NULL, page_size,
                            PROT_READ | PROT_WRITE | PROT_EXEC,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (trampoline == MAP_FAILED) { LOGE("mmap trampoline failed"); return; }

    // Trampoline: original 16 bytes + abs jump back to target+16
    memcpy(trampoline, original_code, 16);
    emit_abs_jump((char *)trampoline + 16, (char *)target + 16);
    g_original = (openAt_jni_t)trampoline;

    // Make target writable, patch it
    void *page = (void *)((uintptr_t)target & ~(page_size - 1));
    if (mprotect(page, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        LOGE("mprotect failed"); munmap(trampoline, page_size); return;
    }

    emit_abs_jump(target, (void *)my_handler);
    g_hook_installed = 1;
    snprintf(g_hook_status, sizeof(g_hook_status), "installed_trampoline=%p", trampoline);
    LOGI("Inline hook installed! trampoline=%p", trampoline);
}

// ── Method 1: dlsym (name-based JNI lookup) ──
static void try_dlsym(void) {
    if (g_hook_installed) return;
    void *target = dlsym(RTLD_DEFAULT, "Java_bin_mt_test_MainActivity_openAt");
    if (target) {
        LOGI("Method 1 success: found via dlsym at %p", target);
        snprintf(g_hook_status, sizeof(g_hook_status), "dlsym_OK_%p", target);
        install_hook_on(target);
    } else {
        LOGW("Method 1 failed: symbol not exported");
        snprintf(g_hook_status, sizeof(g_hook_status), "dlsym_FAIL");
    }
}

// ── Method 2: Hook RegisterNatives in JNINativeInterface table ──
// The JNINativeInterface struct is allocated in process memory.
// RegisterNatives offset in the function table (Android jni.h):
// After ~215 function pointers from GetVersion onward.
// We scan the table for a callable pointer to find the right slot.

static JNIEnv *g_env = NULL;  // saved from hookApkPath

// Our replacement RegisterNatives
typedef jint (*RegisterNatives_t)(JNIEnv*, jclass, const JNINativeMethod*, jint);
static RegisterNatives_t g_real_RegisterNatives = NULL;

static jint my_RegisterNatives(JNIEnv *env, jclass clazz,
                                const JNINativeMethod *methods, jint nMethods) {
    jint result = g_real_RegisterNatives(env, clazz, methods, nMethods);

    if (!g_hook_installed) {
        // Check if this registration includes "openAt"
        for (int i = 0; i < nMethods; i++) {
            if (strcmp(methods[i].name, "openAt") == 0) {
                LOGI("Method 2: RegisterNatives captured openAt at %p", methods[i].fnPtr);
                snprintf(g_hook_status, sizeof(g_hook_status), "RegisterNatives_OK_%p", methods[i].fnPtr);
                install_hook_on(methods[i].fnPtr);
                break;
            }
        }
    }

    return result;
}

#include <sys/uio.h>
#include <errno.h>
// process_vm_writev may not be available at link time (API 21 minSdk)
// Load it at runtime from libc.so
typedef ssize_t (*process_vm_writev_t)(pid_t, const struct iovec*, unsigned long,
                                        const struct iovec*, unsigned long, unsigned long);
static process_vm_writev_t my_pvm_writev = NULL;

static void setup_RegisterNatives_hook(JNIEnv *env) {
    if (g_real_RegisterNatives) return;

    g_env = env;

    // Load process_vm_writev at runtime (API 23+, but available on most devices)
    if (!my_pvm_writev) {
        void *libc = dlopen("libc.so", RTLD_NOLOAD | RTLD_LAZY);
        if (libc) {
            my_pvm_writev = (process_vm_writev_t)dlsym(libc, "process_vm_writev");
            dlclose(libc);
        }
        if (!my_pvm_writev) {
            LOGE("process_vm_writev not available (pre-API23 or restricted)");
            snprintf(g_hook_status, sizeof(g_hook_status), "pvm_writev_UNAVAIL");
            return;
        }
    }

    // The JNINativeInterface table is at (*env).
    void **table = (void **)(void *)(*env);
    void *regFunc = (void *)((*env)->RegisterNatives);
    
    // Find RegisterNatives by scanning the table
    int regIdx = -1;
    for (int i = 0; i < 250; i++) {
        if (table[i] == regFunc) {
            regIdx = i;
            break;
        }
    }
    
    if (regIdx < 0) {
        LOGE("Could not find RegisterNatives in JNINativeInterface table");
        snprintf(g_hook_status, sizeof(g_hook_status), "RegNatives_table_NOT_FOUND");
        return;
    }
    
    LOGI("Found RegisterNatives at table[%d] = %p", regIdx, regFunc);
    
    // Save original RegisterNatives
    g_real_RegisterNatives = (RegisterNatives_t)regFunc;
    
    // Use process_vm_writev to write to protected memory.
    // This syscall bypasses page permissions without needing mprotect.
    void *my_fn = (void *)my_RegisterNatives;
    struct iovec local_iov = { .iov_base = &my_fn, .iov_len = sizeof(my_fn) };
    struct iovec remote_iov = { .iov_base = &table[regIdx], .iov_len = sizeof(table[regIdx]) };
    
    ssize_t written = my_pvm_writev(getpid(), &local_iov, 1, &remote_iov, 1, 0);
    
    if (written != (ssize_t)sizeof(my_fn)) {
        LOGE("process_vm_writev failed: written=%zd errno=%d", written, errno);
        snprintf(g_hook_status, sizeof(g_hook_status), "pvm_writev_FAIL_%d", errno);
        g_real_RegisterNatives = NULL;
        return;
    }
    
    LOGI("RegisterNatives table hook installed! idx=%d via process_vm_writev", regIdx);
    snprintf(g_hook_status, sizeof(g_hook_status), "RegNatives_hook_idx=%d", regIdx);
}


// ── Library detection (cross-namespace via /proc/self/maps) ──
static int is_libtest_loaded(void) {
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) return 0;
    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), maps)) {
        if (strstr(line, "libtest.so")) { found = 1; break; }
    }
    fclose(maps);
    return found;
}

// ── Polling thread ──
static void *poll_thread_impl(void *arg) {
    (void)arg;
    for (int i = 0; i < 15; i++) {
        sleep(1);
        if (g_hook_installed) break;
        try_dlsym();
    }
    return NULL;
}

// ── Entry point (called from mt_jni.c with JNIEnv) ──
void inline_hook_init(JNIEnv *env) {
    LOGI("init");

    // Save env for RegisterNatives hook
    g_env = env;

    // Method 1: try dlsym immediately
    try_dlsym();

    // Method 2: hook RegisterNatives in case libtest.so uses JNI_OnLoad
    if (!g_hook_installed) {
        LOGI("Trying RegisterNatives hook (for JNI_OnLoad-based registration)");
        setup_RegisterNatives_hook(env);
    }

    // Start polling thread as final fallback
    if (!g_hook_installed) {
        LOGI("Starting polling thread");
        pthread_t thread;
        if (pthread_create(&thread, NULL, poll_thread_impl, NULL) == 0)
            pthread_detach(thread);
    }
}
