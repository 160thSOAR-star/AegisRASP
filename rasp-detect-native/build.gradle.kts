plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.rasp.detect"
    compileSdk = 35
    buildToolsVersion = "35.0.0"
    ndkVersion = "27.1.12297006"

    defaultConfig {
        minSdk = 30
        // 只保留 64 位：RASP 依赖 pidfd/clone3/statx 等现代接口，64 位内核行为一致可验证
        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
        externalNativeBuild {
            ndkBuild {
                // 纯 C 实现，不使用 C++ STL
                arguments += listOf("APP_PLATFORM=android-30")
                cFlags += listOf("-O2", "-fvisibility=hidden", "-fno-stack-protector", "-Wall", "-Wextra")
            }
        }
        consumerProguardFiles("consumer-rules.pro")
    }

    externalNativeBuild {
        // 使用 NDK 自带 ndk-build（CMake 在部分 Windows 环境下会对编译器 ABI 探测崩溃）
        ndkBuild {
            path = file("src/main/cpp/Android.mk")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
        debug {
            isJniDebuggable = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        buildConfig = false
    }
    packaging {
        jniLibs {
            useLegacyPackaging = false
        }
    }
}

dependencies {
    implementation("androidx.annotation:annotation:1.9.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
}
