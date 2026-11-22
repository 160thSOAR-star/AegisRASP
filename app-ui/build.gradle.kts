import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// ---------------------------------------------------------------------------
// 签名配置：私钥与口令都不入库。
// 本地打包前请创建 keystore/keystore.properties（格式见 keystore/README.md），
// 该文件与 keystore/*.jks 均已被 .gitignore 排除。
// 若两者都不存在，release 产物将不签名、debug 使用默认调试签名，源码仍可直接编译。
// ---------------------------------------------------------------------------
val keystorePropsFile = rootProject.file("keystore/keystore.properties")
val keystoreProps = Properties().apply {
    if (keystorePropsFile.exists()) keystorePropsFile.inputStream().use { load(it) }
}
val releaseKeystoreFile = rootProject.file(
    keystoreProps.getProperty("storeFile") ?: "keystore/aegis-release.jks"
)
val hasReleaseSigning = keystorePropsFile.exists() && releaseKeystoreFile.exists()

android {
    namespace = "com.rasp.detect.ui"
    compileSdk = 36
    buildToolsVersion = "36.0.0"
    ndkVersion = "27.1.12297006"

    defaultConfig {
        applicationId = "com.rasp.detect.aegis"
        minSdk = 30
        targetSdk = 36
        versionCode = 6
        versionName = "2.0.0-beta"
        resourceConfigurations += listOf("zh", "en")
        // 与 native 模块保持一致：只保留 64 位 ABI
        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    signingConfigs {
        create("aegisRelease") {
            storeFile = releaseKeystoreFile
            storePassword = keystoreProps.getProperty("storePassword")
            keyAlias = keystoreProps.getProperty("keyAlias") ?: "aegis"
            keyPassword = keystoreProps.getProperty("keyPassword")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            signingConfig = if (hasReleaseSigning) signingConfigs.getByName("aegisRelease") else null
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        debug {
            applicationIdSuffix = ".debug"
            // 本地有私钥时沿用同一把钥匙（与 release 同证书，便于统一校验）；
            // 没有私钥时退回默认调试签名，保证 clone 下来即可构建。
            signingConfig = if (hasReleaseSigning) {
                signingConfigs.getByName("aegisRelease")
            } else {
                signingConfigs.getByName("debug")
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
        freeCompilerArgs += listOf("-opt-in=kotlin.RequiresOptIn")
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

if (!hasReleaseSigning) {
    logger.warn(
        "[AegisRASP] 未找到 keystore/keystore.properties 或签名私钥，" +
            "release 产物将不签名。正常打包请按 docs/06-签名与迭代.md 配置本地签名文件。"
    )
}

dependencies {
    implementation(project(":rasp-detect-native"))

    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-ktx:2.8.7")
    implementation("androidx.datastore:datastore-preferences:1.1.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")

    val composeBom = platform("androidx.compose:compose-bom:2024.10.01")
    implementation(composeBom)
    androidTestImplementation(composeBom)
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    debugImplementation("androidx.compose.ui:ui-tooling")
}
