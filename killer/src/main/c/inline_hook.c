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
    LOGI("Inline hook installed! trampoline=%p", trampoline);
}

// ── Method 1: dlsym (name-based JNI lookup) ──
static void try_dlsym(void) {
    if (g_hook_installed) return;
    void *target = dlsym(RTLD_DEFAULT, "Java_bin_mt_test_MainActivity_openAt");
    if (target) {
        LOGI("Method 1 success: found via dlsym at %p", target);
        install_hook_on(target);
    } else {
        LOGW("Method 1 failed: symbol not exported");
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
                install_hook_on(methods[i].fnPtr);
                break;
            }
        }
    }

    return result;
}

static void setup_RegisterNatives_hook(JNIEnv *env) {
    if (g_real_RegisterNatives) return;  // already set up

    g_env = env;

    // The JNINativeInterface is at (*env) or env->functions depending on ABI
    // env is JNIEnv*, *env is JNINativeInterface
    struct JNINativeInterface *table = (struct JNINativeInterface *)(*env);

    // We need to find the RegisterNatives entry. The offset varies by Android
    // version. Instead of hardcoding, we scan for it:
    // RegisterNatives is the ONLY function that takes (JNIEnv*, jclass, const JNINativeMethod*, jint)
    // We can identify it by the function signature at runtime.
    //
    // Simpler: ART's JNI function table is stable across versions for the same
    // architecture. On ARM64 Android (all modern versions), find it at a known
    // offset. We use a heuristic: scan for a function pointer that lands in
    // libart.so and has the right calling convention.
    //
    // Even simpler: just find the table, make it writable, and patch entry by
    // scanning for the existing function pointer.

    // On Android, JNINativeInterface starts with reserved[0..3] (4 pointers),
    // then GetVersion, FindClass, etc.
    // RegisterNatives is typically at offset ~215-220 entries.
    // But we can find it by looking for the function pattern.

    // Simplest approach: make the whole table writable, then patch ALL entries
    // to our proxy that forwards to the original. This is complex.
    //
    // Alternative: Just use the known offset from the JNI spec:
    // RegisterNatives is at index 215 in the standard JNI function table
    // (Android uses the same layout).

    // On Android ARM64, the function table is an array of void* pointers.
    // Each entry is 8 bytes. The table pointer IS the array.
    // Let's find RegisterNatives by iterating until we find a function in libart.so
    // that matches the pattern of our known RegisterNatives.

    // Actually, let me just try the approach of patching the table entry directly.
    // We'll use a brute force scan: find the offset of RegisterNatives by looking
    // for any function pointer that's within libart.so (system library).

    // But the SIMPLEST way: just replace the entire table entry for RegisterNatives.
    // We know the function signature: 4 pointer-sized args (env, clazz, methods, nMethods)
    // and returns jint.

    // On Android jni.h, RegisterNatives is after ~215 entries.
    // Let me use a dynamic approach: find RegisterNatives by calling it normally
    // and seeing which table entry it uses.

    // Wait, I can just USE the env directly. But I need the actual function pointer,
    // not the table entry.

    // OK let me think clearly. We have (*env)->RegisterNatives which resolves to
    // the function pointer via the table. But I need to MODIFY the table entry
    // so that (*env)->RegisterNatives points to MY function.

    // The table is at the address (*env) (which is JNINativeInterface* = void**)
    // Each entry is a function pointer.
    // I need to find WHICH entry is RegisterNatives.

    // Approach: use the C struct to get the offset
    // Since JNINativeInterface is a struct, we can compute the offset by:
    // offsetof(struct JNINativeInterface, RegisterNatives)

    // But we can't use offsetof easily in C for internal structs.
    // Instead, manually calculate.

    // Actually, the SIMPLEST approach: just scan for the RegisterNatives
    // function signature using the existing table.

    // We can identify RegisterNatives by its return type (jint) and arg types.
    // But in the function table, all entries just look like function pointers.

    // Let me use a different method: Don't modify the table.
    // Instead, get the RegisterNatives function address from the table,
    // then use our inline hook on that function address itself.
    // This works even if the function is in libart.so, because we use
    // mprotect + absolute jump.

    // Get the actual RegisterNatives function pointer
    void *regPtr = (void *)((*env)->RegisterNatives);
    LOGI("RegisterNatives function at %p (libart.so)", regPtr);

    // Save it for calling later
    g_real_RegisterNatives = (RegisterNatives_t)regPtr;

    // Install inline hook on RegisterNatives in libart.so
    // Save original first instruction
    uint32_t orig[4];
    memcpy(orig, regPtr, 16);

    // Allocate trampoline
    long page_size = sysconf(_SC_PAGESIZE);
    void *tramp = mmap(NULL, page_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (tramp == MAP_FAILED) { LOGE("mmap tramp failed"); return; }

    // Build trampoline: original 16 bytes + abs jump back to regPtr+16
    memcpy(tramp, orig, 16);
    emit_abs_jump((char *)tramp + 16, (char *)regPtr + 16);
    g_real_RegisterNatives = (RegisterNatives_t)tramp;

    // Make libart's RegisterNatives page writable
    void *page = (void *)((uintptr_t)regPtr & ~(page_size - 1));
    if (mprotect(page, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        LOGE("mprotect on libart.so RegisterNatives FAILED (expected on Android 10+)");
        munmap(tramp, page_size);
        g_real_RegisterNatives = (RegisterNatives_t)regPtr;  // restore
        LOGW("RegisterNatives hook failed, falling back to dlsym polling only");
        return;
    }

    // Patch RegisterNatives to our hook
    emit_abs_jump(regPtr, (void *)my_RegisterNatives);
    LOGI("RegisterNatives hook installed!");
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
