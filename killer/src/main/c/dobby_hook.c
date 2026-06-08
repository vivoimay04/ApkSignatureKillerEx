/**
 * Dobby-based inline hook for SVC openAt bypass.
 *
 * Hooks the JNI function Java_bin_mt_test_MainActivity_openAt
 * in libtest.so to redirect APK file reads — even those made
 * via raw SVC syscall — because it intercepts at the function
 * ENTRY level, not the PLT/GOT level.
 *
 * Since libtest.so is NOT loaded when KillerApplication init runs,
 * we use xhook to intercept android_dlopen_ext and install the
 * Dobby hook at the moment libtest.so appears.
 */

#include <string.h>
#include <dlfcn.h>
#include <jni.h>
#include "xhook.h"
#include "xh_log.h"
#include "dobby.h"

// Global paths set by hookApkPath in mt_jni.c
extern const char *apkPath__;
extern const char *repPath__;

// Original openAt JNI function pointer
typedef jint (*openAt_jni_t)(JNIEnv *, jclass, jstring);
static openAt_jni_t old_openAt_jni = NULL;

// Our replacement: called instead of Java_bin_mt_test_MainActivity_openAt
static jint my_openAt_jni(JNIEnv *env, jclass clazz, jstring path) {
    const char *path_utf = (*env)->GetStringUTFChars(env, path, 0);
    jint result = -1;

    if (apkPath__ && repPath__ && strcmp(path_utf, apkPath__) == 0) {
        // Redirect to origin.apk
        XH_LOG_INFO("DobbyHook: redirecting openAt(%s) -> %s", path_utf, repPath__);
        jstring repPathJ = (*env)->NewStringUTF(env, repPath__);
        result = old_openAt_jni(env, clazz, repPathJ);
        (*env)->DeleteLocalRef(env, repPathJ);
    } else {
        // Pass through
        result = old_openAt_jni(env, clazz, path);
    }

    (*env)->ReleaseStringUTFChars(env, path, path_utf);
    return result;
}

// Called when we detect libtest.so is loaded
static void install_openat_hook(void) {
    // Find the JNI openAt function in libtest.so
    void *libtest = dlopen("libtest.so", RTLD_NOLOAD);
    if (!libtest) {
        XH_LOG_WARN("DobbyHook: libtest.so not loaded yet, will retry");
        return;
    }

    // Resolve symbol from libtest.so using Dobby
    void *target = DobbySymbolResolver("libtest.so", "Java_bin_mt_test_MainActivity_openAt");
    if (!target) {
        XH_LOG_ERROR("DobbyHook: cannot find Java_bin_mt_test_MainActivity_openAt in libtest.so");
        dlclose(libtest);
        return;
    }

    XH_LOG_INFO("DobbyHook: found target at %p", target);
    
    // Install the hook
    int ret = DobbyHook(target, (void *)my_openAt_jni, (void **)&old_openAt_jni);
    if (ret == 0) {
        XH_LOG_INFO("DobbyHook: installed successfully! old=%p", old_openAt_jni);
    } else {
        XH_LOG_ERROR("DobbyHook: installation failed with code %d", ret);
    }
    
    dlclose(libtest);
}

// ── dlopen hook to catch libtest.so loading ──

static void *(*old_android_dlopen_ext)(const char *, int, const void *);
static void *dlopen_ext_impl(const char *filename, int flags, const void *extinfo) {
    void *handle = old_android_dlopen_ext(filename, flags, extinfo);
    if (handle && filename && strstr(filename, "libtest.so")) {
        XH_LOG_INFO("DobbyHook: libtest.so loaded via dlopen, installing hook");
        install_openat_hook();
    }
    return handle;
}

// Called from mt_jni.c's hookApkPath to register the dlopen hook
void dobby_hook_init(void) {
    XH_LOG_INFO("DobbyHook: registering android_dlopen_ext hook");
    xhook_register(".*\\.so$", "android_dlopen_ext",
                   dlopen_ext_impl, (void **)&old_android_dlopen_ext);
    xhook_refresh(0);
    
    // Also try immediately in case libtest.so is already loaded
    install_openat_hook();
}
