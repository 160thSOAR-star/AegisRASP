# 交接说明（给下一个对话 / 下一位维护者）

> 写给接手这个项目的 AI 或工程师：先读这份，再动手。
> 它记录**当前状态、为什么这样设计、以及已经踩过的坑**——很多坑会以"看起来能编译但结果全错"的形式复现。

---

## 0. 一句话背景

Aegis RASP 是一个 Android 15（API 35）上、**非 Root、纯本地**的 KernelSU 隐藏环境检测 App：
51 个检测项、Native（C11/bionic）核心 + Compose Material3 界面、加权打分、可导出报告。

- 工程目录：`E:\安卓检测项目`
- 当前版本：**1.0.1**（versionCode 3）
- 可用产物：`dist/AegisRASP-1.0.1-release.apk`（2.30 MB，SHA-256 `B98ACACE…38D4B984`）
- 包名：`com.rasp.detect.aegis`；ABI：arm64-v8a / x86_64；minSdk 30 / targetSdk 35

---

## 1. 先建立正确的预期

| 事实 | 含义 |
| --- | --- |
| **从未在真机/模拟器上跑过** | 所有分数区间都是静态推算；第一次上真机大概率要调阈值 |
| 已做的验证 | 双 ABI 零警告编译、`.so` 仅导出 `JNI_OnLoad`、JNI 签名与 dex 对得上、APK v2 签名、`lintVitalRelease` 通过、新增 ID 确实在 `.so` 里 |
| 文档里的数字 | `04-测试矩阵` 是推算值；`02/03` 的"是否可擦除"是分析结论，不是实测 |
| 跨进程 `/proc` | 普通应用读 init/system_server **几乎必然 EACCES**，相关项会 `available=false`（这是"无法判定"，不是"安全"） |

**所以第一优先级不是加功能，而是拿一台 Android 15 设备做基线校准。**

---

## 2. 设计思路（改动前必须理解，否则会越改越糟）

### 2.1 核心命题
> 不检测"是否 Root"，检测"隐藏行为是否让系统各处说法互相矛盾"。
> 伪造一个视图便宜，让所有视图同时自洽很贵。

### 2.2 五条准则（代码里都有对应实现）
1. **优先不可伪造的物理事实**：`statx.stx_mnt_id` 必须出现在 mountinfo；`status` 的 Uid 必须等于 `getuid()`；
   `statfs` 的 `ST_RDONLY` 必须等于 mountinfo 的 `ro`；`btime ≈ now − BOOTTIME`；`openat2` 与 `openat` 字节一致；
   `getdents` 里没有的 fd，按名字也不该打开成功。
2. **至少两个独立来源**：libc / 直调 syscall / pidfd / clone3 子进程 / 另一条 syscall。
3. **不可用 ≠ 安全**：每个检测项是三态（命中 / 未命中 / 不可用），报告必须显式标 `available=false` + error。
4. **检测器自身是被攻击对象**：直调 syscall、序言字节校验、代码段快照、JNI 表校验、
   `dladdr`+段权限、`openat2` 双路径；反 Hook（AHK-001..006）命中直接判 85 分下限。
5. **只取证不攻击**：不写系统、不 ptrace、不加载内核模块、无网络权限、无 root 依赖。

### 2.3 架构与信任分层
```
Compose UI（最不可信，LSPosed 主战场）
  → ViewModel → RaspEngine → JavaProbes（只能做 PackageManager/binder/属性这类必须 Java 的事）
    → JNI（5 个方法：runDetect / submitEvidence / cancelDetect / nativeVersion / readProperty）
      → Native 核心（C，直调 syscall，证据流式回传）
```
- **不要**把检测逻辑写进 Compose 组件；
- **不要**为了省事在 Java 层自己打分——Java 只提交证据，聚合与打分在 `rasp_score.c`；
- JNI 方法用 `RegisterNatives` 注册、符号不导出；R8 规则 `-keep class com.rasp.detect.** { *; }` 不能删。

### 2.4 打分模型（改之前想清楚）
- 权重：强 30 / 间接 10 / 弱 3，乘 confidence；
- 同类（category+grade）叠加 `0.7^n` 衰减（n 封顶 3），避免"一个事实的多种说法"刷分；
- 单条强证据 → 分数下限 25；反 Hook → 下限 85；只有 1 条弱线索时总分 ×0.5；
- 阈值 20 / 50；等级用未取整分数判定；
- 分数回答"多危险"，confidence 回答"多确定"，两者不可合并。

---

## 3. 已经踩过的坑（按"复现概率"排序）

### 3.1 Windows 中文路径
- **AGP 直接拒绝构建**：`Your project path contains non-ASCII characters` → `gradle.properties` 里必须有 `android.overridePathCheck=true`。
- **CMake 崩溃**：本机 cmake 3.22.1 在编译器 ABI 探测阶段 `0xC0000409` 退出 → 已改用 **ndk-build**（`src/main/cpp/Android.mk`）。
  `CMakeLists.txt` 保留但不参与构建；不要随手切回 CMake 而不验证。
- **稳妥构建方式**：目录联接出纯 ASCII 路径再构建
  ```powershell
  New-Item -ItemType Junction -Path 'E:\aegis-build' -Target 'E:\安卓检测项目'
  cd 'E:\aegis-build'
  ```
  产物仍落回真实目录。

### 3.2 PowerShell 编码（最隐蔽、破坏性最大）
- `Get-Content -Raw` 在 PS 5.1 **默认按 ANSI 读 UTF-8 文件**，再用 `WriteAllText` 写回会把中文注释/字符串**永久损坏**。
  我在本项目里因此重写了 4 个 C 文件。
- 规则：**改源码只用 `read` / `edit` / `write` 工具**；必须用 PowerShell 时显式
  `Get-Content -Encoding UTF8` + `[IO.File]::WriteAllText(path, s, New-Object Text.UTF8Encoding($false))`。
- 用 `powershell -File script.ps1` 跑带中文路径的脚本时，文件**必须带 UTF-8 BOM**，否则路径乱码；
  更稳的写法是用 `$PSScriptRoot` 推导路径，脚本里不写中文。
- 验证方法：`[Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($p))` 能正常显示中文，
  或严格 UTF-8 解码不抛异常。

### 3.3 依赖与 SDK 拉取
- `services.gradle.org` 会重定向到 GitHub，本机不通 → 用腾讯云镜像（wrapper 的 `distributionUrl` 已改）。
- AGP 会尝试在线安装 **build-tools 34** 与 **platform-tools 37.0.3**（从 dl.google.com，极慢）：
  解决是显式 `buildToolsVersion = "35.0.0"`，并把 `platform-tools`（37.0.1）放进 SDK 目录 + `source.properties` 正确。
- SDK 组件（platform-35、build-tools、NDK r27b）来自 `https://mirrors.cloud.tencent.com/AndroidSDK/`；
  `licenses/android-sdk-license` 需要手写哈希，否则 AGP 拒绝。
- Gradle 8.9 在 `E:\安卓检测项目\.tools\gradle-8.9`；`.tools` 还有约 1.3 GB 下载缓存（可删）。

### 3.4 JNI 契约
- Kotlin 侧签名必须与 `g_methods` 里**逐字符一致**；改签名后必须重新 `dexdump` 核对，否则运行时 `UnsatisfiedLinkError`。
- 回调接口用 `FindClass("com/rasp/detect/RaspNative$EvidenceSink")` 取 `GetMethodID`，
  **不要**用 `GetObjectClass(sink)`（lambda 实现类上找方法不稳）。
- `NewStringUTF` 是 modified UTF-8：只能保证 BMP（本项目只有 ASCII + 汉字，安全）；
  报告超过 240 KB 会走降级 JSON。
- 新增 native 方法要三处同步：`RaspNative.kt` 的 `external fun`、`rasp_jni.c` 的 `g_methods`、C 函数本体。

### 3.5 手写 JSON 的雷
- 本项目 native 侧不用第三方库，JSON 全靠 `rb_printf` 拼——**极易拼出畸形串**。
  曾出现 `"antiHook":"hit":true`（缺花括号）、`"raw":"value":"..."`（多一层键）等错误。
- 规则：只用 `rb_json_kv_*` / `rb_json_str_value`，不要手写 `"key":`；改完用 `jq`/`JSONObject` 实测解析。

### 3.6 白名单（设计变更最多的地方）
演进史本身就是教训：**第一版"任意片段对整条 raw 做子串匹配"** 导致
`overlay on /system` 被整体豁免、`system_server` 自命中、ID 分支永远不可达（ID 只有 7 字符但门槛是 ≥8）、
多词锚点被空格分隔打散。现行为 v3：

1. 片段与检测项 ID **完全相等** → 显式豁免（任何等级）；
2. 否则片段必须 ≥10 字节、不以 `/` 开头、不在通用进程名黑名单（system_server/zygote64/zygote/init/surfaceflinger/servicemanager）；
3. **强证据**额外要求片段 ≥14 字节且含 `=`、`.` 或 ` on `；
4. 片段之间用 `;` 分隔（`rasp_extract_array` 的 `append_token`），多词锚点才不会被拆散。

**新增白名单条目时先想：它会不会出现在某条强证据的 raw 里？**

### 3.7 误报的三大来源
- **ART 固有行为**：`memfd:jit-cache` 是正常 JIT 映射；`libart.so` 的 rw 数据段是正常映射。
  → `rasp_maps_stats` 排除路径含 `jit/dalvik/boot.art/boot.oat` 的映射，`art_writable` 只统计 `w+x` 代码段。
- **bionic 的 ifunc/别名跳转桩**：函数入口出现 `B`/`BL` 是合法的。
  → 必须解码跳转目标，**只有目标落在本模块外才判 Hook**（`rasp_memory.c::rasp_check_function_entry`）。
- **大块匿名可写映射**：ART 堆天然很多。→ `big_anon_rw` 阈值放宽到 >12 且只给 0.15 权重。

### 3.8 沙箱（clone3）
- 子进程**不能用 malloc、不能加锁、不能碰 Java**（fork 后锁状态不一致）。
- 子进程必须回填 `shm->child_pid` 与 `ppid`：早期漏了回填，导致 `SBX-001` 在**每台干净设备上**都以 0.5 置信度命中（假阳性）。
- 等待超时 1500 ms，超时 `SIGKILL` 回收；`clone3` 失败回退 `clone(SIGCHLD)`。

### 3.9 版本/签名/发版
- 密钥：`keystore/aegis-release.jks`（**PKCS12**，别名 `aegis`，口令从本地不入库的 `keystore/keystore.properties` 读取，证书 SHA-256 `93:1E:E6:…`）。
- 覆盖升级三条件：`versionCode` 递增、同签名、同包名。换钥 = 换身份，只能卸载重装。
- 应用内「关于 → 更新日志」是 `AboutScreen.kt` 里的字符串常量，**改日志必须改代码重新打包**；
  `CHANGELOG.md` 只是仓库记录，不影响 APK。
- 每次发版要同步：`versionCode/versionName`、`AboutScreen.kt`、`CHANGELOG.md`、`README §8`、`docs/05`、`docs/06`。

---

## 4. 不要做的事（违反会直接破坏设计）

- ❌ 加 `INTERNET` 权限或任何远程校验（SafetyNet / Play Integrity）——设计前提是"纯本地"。
- ❌ 把检测逻辑写进 Compose 组件，或让 Java 层自己算分。
- ❌ 用 su 路径扫描、`ro.debuggable` 单点判断、busybox 检测当主要依据。
- ❌ 需要 root 才能运行的检测。
- ❌ 检测失败/不可读时输出"安全"——这是最危险的错误。
- ❌ 改动白名单后不做"反向检查"（拿新片段去 51 项 raw 里搜，确认只豁免预期 ID）。

---

## 5. 开工清单（复制即可用）

```powershell
# 环境（按本机实际路径填写）
$env:JAVA_HOME='<你的 JDK 17 目录>'
$env:ANDROID_HOME='<你的 Android SDK 目录>'
$env:ANDROID_SDK_ROOT=$env:ANDROID_HOME

# 构建（工程路径含中文时，用 ASCII 联接规避工具链问题）
New-Item -ItemType Junction -Path 'C:\aegis-build' -Target '<工程根目录>' -Force -ErrorAction SilentlyContinue
cd 'C:\aegis-build'
.\gradlew.bat --no-daemon :app-ui:assembleRelease

# 校验
& "$env:ANDROID_HOME\build-tools\35.0.0\apksigner.bat" verify --print-certs `
  'app-ui\build\outputs\apk\release\app-ui-release.apk'

# 归档
Copy-Item 'app-ui\build\outputs\apk\release\app-ui-release.apk' `
  'dist\AegisRASP-<version>-release.apk' -Force
```

**建议阅读顺序**：`README.md` → `CHANGELOG.md` → `docs/00-设计理念.md` → `docs/01-检测项清单.md`
→ `docs/04-测试矩阵.md` → `docs/06-签名与迭代.md`。改代码前先读 `docs/02`（误报面）。

---

## 6. 最该做的下一步（按价值排序）

1. **真机基线**：Android 15 干净机 + KSU 裸装各跑一次，记录分数/命中集合/耗时，回填 `docs/04`；
2. **标定三个新项**：`MNT-008/009`（厂商 ro/rw 与 dev 差异）、`INJ-005`（模拟器误报，建议 ID 豁免）、
   `AHK-006`（openat2 在定制内核是否可用）；
3. **性能**：模块预算最坏合计约 20.8 s，真机需确认"完整模式 < 6 s"是否成立，不成立就调整预算或降级采样；
4. **可复现性**：把 `local.properties`、NDK 版本、Gradle wrapper 校验和写进 CI；
5. 功能层：`AboutScreen` 的日志与 `CHANGELOG.md` 自动同步（改一处即可）、报告 diff（同一设备多次检测对比）。

---

## 7. 交接资产清单

| 路径 | 说明 |
| --- | --- |
| `dist/AegisRASP-1.0.1-release.apk` | 当前可安装产物（已签名，versionCode 3） |
| `dist/AegisRASP-1.0.1-rc-release.apk` | 1.0.1 的候选版（versionCode 2），回溯/对比用 |
| `dist/AegisRASP-1.0.0-release.apk` | 初版（41 项），回归对比用 |
| `keystore/aegis-release.jks` | 签名私钥，**丢失即无法升级** |
| `rasp-detect-native/src/main/cpp/` | 14 个 C 文件（引擎 + 9 类检测 + 沙箱 + 打分 + JNI） |
| `app-ui/src/main/java/com/rasp/detect/ui/` | Compose 界面（三标签、组件、导出） |
| `docs/00`–`docs/06` | 设计、检测项、误报、对抗、测试矩阵、构建记录、签名 |
| `CHANGELOG.md` | 版本变更唯一权威记录 |

> `dist/` 下的 APK 与 `keystore/` 下的私钥不计入仓库（见 `.gitignore`）：APK 作为 Release 附件分发，私钥只在本地维护。
