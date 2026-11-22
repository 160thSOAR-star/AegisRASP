cmake_minimum_required(VERSION 3.22.1)
project(aegisrasp C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_library(aegisrasp SHARED
        rasp_syscall.c
        rasp_util.c
        rasp_memory.c
        rasp_compat.c
        rasp_sandbox.c
        rasp_checks_mount.c
        rasp_checks_ksu.c
        rasp_checks_kernel.c
        rasp_checks_zygisk.c
        rasp_checks_inject.c
        rasp_checks_security.c
        rasp_checks_extra.c
        rasp_checks_antihook.c
        rasp_score.c
        rasp_jni.c)

target_compile_options(aegisrasp PRIVATE
        -O2
        -fvisibility=hidden
        -fno-stack-protector
        -Wall
        -Wextra
        -Wno-unused-parameter)

find_library(log-lib log)
find_library(android-lib android)

target_link_libraries(aegisrasp PRIVATE
        ${log-lib}
        ${android-lib}
        m
        dl)

# 与 Android 15 (API 35) 对齐
target_compile_definitions(aegisrasp PRIVATE __ANDROID_API__=35)
