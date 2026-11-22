# RASP native 构建参数（ndk-build 路径；同时保留 CMakeLists.txt 供 CMake 构建方式使用）
APP_PLATFORM := android-30
APP_ABI := arm64-v8a x86_64
APP_STL := none
APP_OPTIM := release
APP_CFLAGS := -O2 -fvisibility=hidden -fno-stack-protector
# Android 15 起存在 16KB 页设备，Android 16 起是硬性要求：
# 让 NDK 以 16KB 对齐生成 ELF 段（NDK r27+ 支持该开关）。
APP_SUPPORT_FLEXIBLE_PAGE_SIZES := true
