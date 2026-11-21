# RASP native 构建参数（ndk-build 路径；同时保留 CMakeLists.txt 供 CMake 构建方式使用）
APP_PLATFORM := android-30
APP_ABI := arm64-v8a x86_64
APP_STL := none
APP_OPTIM := release
APP_CFLAGS := -O2 -fvisibility=hidden -fno-stack-protector
