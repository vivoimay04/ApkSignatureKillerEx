/**
 * Minimal ARM64 inline hook for SVC openAt bypass.
 *
 * Uses absolute jump (LDR X17, [PC, #8]; BR X17) which works
 * regardless of distance between target and handler libraries.
 *
 * Overwrites 16 bytes (4 instructions) of the target function.
 * Trampoline saves original 16 bytes then jumps back.
 */

#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>
#include <jni.h>
#include "xhook.h"
#include "xh_log.h"

// External paths set by hookApkPath in mt_jni.c
extern const char *apkPath__;
extern const char *repPath__;

// ── ARM64 helpers ──

// Write an absolute jump: LDR X17, [PC, #8]; BR X17; <8-byte target>
// This is 16 bytes total and reaches any address.
static void emit_abs_jump(void *where, void *target) {
    uint32_t *code = (uint32_t *)where;
    // LDR X17, [PC, #8]  — load from PC+8 (immediately after BR)
    code[0] = 0x58000051;  // LDR X17, #8
    // BR X17
    code[1] = 0xD61F0220;  // BR X17
    // Target address (8 bytes)
    memcpy(&code[2], &target, 8);
    __builtin___clear_cache(where, (char *)where + 16);
}

// ── Original function pointer ──

typedef jint (*openAt_jni_t)(JNIEnv *, jclass, jstring);
static openAt_jni_t g_original = NULL;

// ── Our replacement handler ──

static jint my_handler(JNIEnv *env, jclass clazz, jstring path) {
    const char *path_utf = (*env)->GetStringUTFChars(env, path, 0);
    jint result;

    if (apkPath__ && repPath__ && strcmp(path_utf, apkPath__) == 0) {
        XH_LOG_INFO("InlineHook: redirecting openAt(%s) -> %s", path_utf, repPath__);
        jstring repPath = (*env)->NewStringUTF(env, repPath__);
        result = g_original(env, clazz, repPath);
        (*env)->DeleteLocalRef(env, repPath);
    } else {
        result = g_original(env, clazz, path);
    }

    (*env)->ReleaseStringUTFChars(env, path, path_utf);
    return result;
}

// ── Install the inline hook on Java_bin_mt_test_MainActivity_openAt ──

static int g_hook_installed = 0;

static void install_openat_hook(void) {
    if (g_hook_installed) return;

    const char *func_name = "Java_bin_mt_test_MainActivity_openAt";

    void *target = dlsym(RTLD_DEFAULT, func_name);
    if (!target) {
        XH_LOG_WARN("InlineHook: %s not found (libtest.so not loaded?)", func_name);
        return;
    }
    XH_LOG_INFO("InlineHook: found %s at %p", func_name, target);

    // Save original 4 instructions (16 bytes)
    uint32_t original_code[4];
    memcpy(original_code, target, 16);

    // Allocate executable trampoline (32 bytes min)
    long page_size = sysconf(_SC_PAGESIZE);
    void *trampoline = mmap(NULL, page_size,
                            PROT_READ | PROT_WRITE | PROT_EXEC,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (trampoline == MAP_FAILED) {
        XH_LOG_ERROR("InlineHook: mmap trampoline failed");
        return;
    }

    // Build trampoline: [original 16 bytes] + [abs jump to target+16]
    memcpy(trampoline, original_code, 16);
    emit_abs_jump((char *)trampoline + 16, (char *)target + 16);
    g_original = (openAt_jni_t)trampoline;

    // Make target page writable
    void *page = (void *)((uintptr_t)target & ~(page_size - 1));
    if (mprotect(page, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        XH_LOG_ERROR("InlineHook: mprotect failed");
        munmap(trampoline, page_size);
        return;
    }

    // Overwrite target with abs jump to our handler
    emit_abs_jump(target, (void *)my_handler);

    g_hook_installed = 1;
    XH_LOG_INFO("InlineHook: installed! trampoline=%p", trampoline);
}

// ── dlopen hooks to catch libtest.so loading ──

static void *(*old_android_dlopen_ext)(const char *, int, const void *);
static void *dlopen_ext_impl(const char *filename, int flags, const void *extinfo) {
    void *handle = old_android_dlopen_ext(filename, flags, extinfo);
    if (handle && filename && strstr(filename, "libtest.so")) {
        XH_LOG_INFO("InlineHook: libtest.so loaded (dlopen_ext)");
        install_openat_hook();
    }
    return handle;
}

static void *(*old_dlopen)(const char *, int);
static void *dlopen_impl(const char *filename, int flags) {
    void *handle = old_dlopen(filename, flags);
    if (handle && filename && strstr(filename, "libtest.so")) {
        XH_LOG_INFO("InlineHook: libtest.so loaded (dlopen)");
        install_openat_hook();
    }
    return handle;
}

// ── Called from mt_jni.c's hookApkPath ──

void inline_hook_init(void) {
    XH_LOG_INFO("InlineHook: init");

    // Hook dlopen variants to detect when libtest.so loads
    xhook_register(".*\\.so$", "android_dlopen_ext",
                   (void *)dlopen_ext_impl, (void **)&old_android_dlopen_ext);
    xhook_register(".*\\.so$", "dlopen",
                   (void *)dlopen_impl, (void **)&old_dlopen);
    xhook_refresh(0);

    // Try immediately in case libtest.so is already loaded
    install_openat_hook();
}
