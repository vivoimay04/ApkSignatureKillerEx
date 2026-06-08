/**
 * Minimal ARM64 inline hook for SVC openAt bypass.
 *
 * Overwrites the first instruction of the target function with
 * an unconditional branch (B) to our handler. A trampoline
 * executes the original instruction then branches back.
 *
 * Works at function ENTRY level — catches calls made via SVC
 * because we patch the function itself, not the PLT/GOT.
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

// Encode ARM64 B (unconditional branch) instruction, range ±128MB
static void emit_branch(void *from, void *to) {
    uint32_t *code = (uint32_t *)from;
    int64_t offset = (int64_t)to - (int64_t)from;
    uint32_t instr = 0x14000000 | ((offset >> 2) & 0x03FFFFFF);
    code[0] = instr;
    __builtin___clear_cache(from, (char *)from + 4);
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
        XH_LOG_WARN("InlineHook: %s not found yet (libtest.so not loaded?)", func_name);
        return;
    }
    XH_LOG_INFO("InlineHook: found %s at %p", func_name, target);

    // Save original first instruction
    uint32_t original_instr = *(volatile uint32_t *)target;

    // Allocate executable trampoline
    long page_size = sysconf(_SC_PAGESIZE);
    void *trampoline = mmap(NULL, page_size,
                            PROT_READ | PROT_WRITE | PROT_EXEC,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (trampoline == MAP_FAILED) {
        XH_LOG_ERROR("InlineHook: mmap trampoline failed");
        return;
    }

    // Trampoline: [original instr] + [B back to target+4]
    *(uint32_t *)trampoline = original_instr;
    emit_branch((char *)trampoline + 4, (char *)target + 4);
    g_original = (openAt_jni_t)trampoline;

    // Make target page writable
    void *page = (void *)((uintptr_t)target & ~(page_size - 1));
    if (mprotect(page, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        XH_LOG_ERROR("InlineHook: mprotect failed");
        munmap(trampoline, page_size);
        return;
    }

    // Overwrite first instruction with B to our handler
    emit_branch(target, (void *)my_handler);

    g_hook_installed = 1;
    XH_LOG_INFO("InlineHook: installed! trampoline=%p orig_instr=0x%x", trampoline, original_instr);
}

// ── dlopen hooks to catch libtest.so loading ──

static void *(*old_android_dlopen_ext)(const char *, int, const void *);
static void *dlopen_ext_impl(const char *filename, int flags, const void *extinfo) {
    void *handle = old_android_dlopen_ext(filename, flags, extinfo);
    if (handle && filename && strstr(filename, "libtest.so")) {
        XH_LOG_INFO("InlineHook: libtest.so loaded (dlopen_ext), installing hook");
        install_openat_hook();
    }
    return handle;
}

static void *(*old_dlopen)(const char *, int);
static void *dlopen_impl(const char *filename, int flags) {
    void *handle = old_dlopen(filename, flags);
    if (handle && filename && strstr(filename, "libtest.so")) {
        XH_LOG_INFO("InlineHook: libtest.so loaded (dlopen), installing hook");
        install_openat_hook();
    }
    return handle;
}

// ── Called from mt_jni.c's hookApkPath ──

void inline_hook_init(void) {
    XH_LOG_INFO("InlineHook: init");

    // Hook both dlopen variants to detect when libtest.so loads
    xhook_register(".*\\.so$", "android_dlopen_ext",
                   (void *)dlopen_ext_impl, (void **)&old_android_dlopen_ext);
    xhook_register(".*\\.so$", "dlopen",
                   (void *)dlopen_impl, (void **)&old_dlopen);
    xhook_refresh(0);

    // Also try immediately in case libtest.so is already loaded
    install_openat_hook();
}
