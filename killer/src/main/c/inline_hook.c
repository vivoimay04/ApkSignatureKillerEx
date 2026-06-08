/**
 * Minimal ARM64 inline hook for SVC openAt bypass.
 *
 * Uses absolute jump (LDR X17, [PC, #8]; BR X17) which works
 * at any distance. Polls periodically for libtest.so since
 * ART calls dlopen internally without going through PLT.
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
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

extern const char *apkPath__;
extern const char *repPath__;

// ── ARM64 absolute jump: LDR X17, [PC, #8]; BR X17; <8-byte target> ──

static void emit_abs_jump(void *where, void *target) {
    uint32_t *code = (uint32_t *)where;
    code[0] = 0x58000051;  // LDR X17, [PC, #8]
    code[1] = 0xD61F0220;  // BR X17
    memcpy(&code[2], &target, 8);
    __builtin___clear_cache(where, (char *)where + 16);
}

typedef jint (*openAt_jni_t)(JNIEnv *, jclass, jstring);
static openAt_jni_t g_original = NULL;

// ── Handler ──

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

// ── Install hook ──

static int g_hook_installed = 0;

static void install_openat_hook(void) {
    if (g_hook_installed) {
        LOGI("Hook already installed, skipping");
        return;
    }

    void *lib = dlopen("libtest.so", RTLD_NOLOAD | RTLD_LAZY);
    if (!lib) {
        LOGW("libtest.so not loaded yet");
        return;
    }
    dlclose(lib);

    void *target = dlsym(RTLD_DEFAULT, "Java_bin_mt_test_MainActivity_openAt");
    if (!target) {
        LOGE("Failed to find Java_bin_mt_test_MainActivity_openAt in libtest.so");
        return;
    }
    LOGI("Found Java_bin_mt_test_MainActivity_openAt at %p", target);

    // Disassemble first instruction for debugging
    uint32_t first_instr = *(volatile uint32_t *)target;
    LOGI("First instruction at target: 0x%08x", first_instr);

    // Save original 4 instructions (16 bytes)
    uint32_t original_code[4];
    memcpy(original_code, target, 16);

    // Allocate trampoline
    long page_size = sysconf(_SC_PAGESIZE);
    void *trampoline = mmap(NULL, page_size,
                            PROT_READ | PROT_WRITE | PROT_EXEC,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (trampoline == MAP_FAILED) {
        LOGE("mmap trampoline failed");
        return;
    }

    // Trampoline: original 16 bytes + abs jump back to target+16
    memcpy(trampoline, original_code, 16);
    emit_abs_jump((char *)trampoline + 16, (char *)target + 16);
    g_original = (openAt_jni_t)trampoline;
    LOGI("Trampoline at %p", trampoline);

    // Make target writable, patch it
    void *page = (void *)((uintptr_t)target & ~(page_size - 1));
    if (mprotect(page, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        LOGE("mprotect failed");
        munmap(trampoline, page_size);
        return;
    }

    emit_abs_jump(target, (void *)my_handler);
    g_hook_installed = 1;
    LOGI("Inline hook installed successfully!");
}

// ── Polling thread (fallback since xhook can't hook ART's internal dlopen) ──

static void *poll_thread_impl(void *arg) {
    (void)arg;
    for (int i = 0; i < 15; i++) {  // 15 tries × 1s = 15s max wait
        sleep(1);
        if (g_hook_installed) break;
        install_openat_hook();
    }
    if (g_hook_installed) {
        LOGI("Polling thread: hook installed after polling");
    } else {
        LOGE("Polling thread: FAILED to install hook after 15s");
    }
    return NULL;
}

// ── dlopen hooks (best-effort, may not work on modern ART) ──

#include "xhook.h"

static void *(*old_android_dlopen_ext)(const char *, int, const void *);
static void *dlopen_ext_impl(const char *filename, int flags, const void *extinfo) {
    void *handle = old_android_dlopen_ext(filename, flags, extinfo);
    if (handle && filename && strstr(filename, "libtest.so")) {
        LOGI("libtest.so loaded via dlopen_ext, installing hook");
        install_openat_hook();
    }
    return handle;
}

static void *(*old_dlopen)(const char *, int);
static void *dlopen_impl(const char *filename, int flags) {
    void *handle = old_dlopen(filename, flags);
    if (handle && filename && strstr(filename, "libtest.so")) {
        LOGI("libtest.so loaded via dlopen, installing hook");
        install_openat_hook();
    }
    return handle;
}

// ── Entry point ──

void inline_hook_init(void) {
    LOGI("init");

    // Best-effort: try xhook on dlopen (works on older Android)
    xhook_register(".*\\.so$", "android_dlopen_ext",
                   (void *)dlopen_ext_impl, (void **)&old_android_dlopen_ext);
    xhook_register(".*\\.so$", "dlopen",
                   (void *)dlopen_impl, (void **)&old_dlopen);
    xhook_refresh(0);

    // Try immediately (maybe libtest.so already loaded)
    install_openat_hook();

    if (!g_hook_installed) {
        LOGI("libtest.so not loaded yet, starting polling thread");
        pthread_t thread;
        if (pthread_create(&thread, NULL, poll_thread_impl, NULL) == 0) {
            pthread_detach(thread);
        } else {
            LOGE("Failed to create polling thread");
        }
    }
}
