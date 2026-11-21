LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := aegisrasp
LOCAL_SRC_FILES := \
    rasp_syscall.c \
    rasp_util.c \
    rasp_memory.c \
    rasp_sandbox.c \
    rasp_checks_mount.c \
    rasp_checks_ksu.c \
    rasp_checks_kernel.c \
    rasp_checks_zygisk.c \
    rasp_checks_inject.c \
    rasp_checks_security.c \
    rasp_checks_extra.c \
    rasp_checks_antihook.c \
    rasp_score.c \
    rasp_jni.c

LOCAL_C_INCLUDES := $(LOCAL_PATH)
LOCAL_CFLAGS := -O2 -std=c11 -fvisibility=hidden -fno-stack-protector -Wall -Wextra \
                -Wno-unused-parameter
LOCAL_LDLIBS := -llog -landroid -lm -ldl

include $(BUILD_SHARED_LIBRARY)
