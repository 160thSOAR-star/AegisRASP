# 交接说明（给下一个对话 / 下一位维护者）

> 写给接手这个项目的 AI 或工程师：先读这份，再动手。
> 它记录**当前状态、为什么这样设计、以及已经踩过的坑**——很多坑会以"看起来能编译但结果全错"的形式复现。

> **📌 必读配套文件：[`HANDOVER-2.0.0-beta.md`](HANDOVER-2.0.0-beta.md)**
> 本文件是**长期有效**的设计/坑/禁止事项；那份是**会过期**的当前状态、完整事件时间线、
> 10 条注意事项、按优先级的交接清单，以及对项目与维护者的坦率评价。
> **建议顺序**：先跑那份的 §2 自检 → 读本文 §1–§2 → 再读那份 §3 的事故复盘。
> 两份冲突时，版本/状态类以 `CHANGELOG.md` 与产物为准，设计类以本文为准。

---

## 0. 一句话背景

Aegis RASP 是一个 Android 15–16（API 35–36）上、**非 Root、纯本地**的 KernelSU 隐藏环境检测 App：
51 个检测项、Native（C11/bionic）核心 + Compose Material3 界面、加权打分、可导出报告。

- 工程目录：`E:\安卓检测项目`
- 当前版本：**2.0.0-beta**（versionCode 6；compileSdk/targetSdk **36 / Android 16**）
- 可用产物：`dist/AegisRASP-2.0.0-beta-release.apk`（2,430,987 B，SHA-256 `CCFA3A26…C0A25954`）
- 包名：`com.rasp.detect.aegis`；ABI：arm64-v8a / x86_64；minSdk 30 / targetSdk 36；native 库 16 KB 页对齐

---

## 1. 先建立正确的预期

| 事实 | 含义 |
| --- | --- |
| **真机验证：无系统性基线** | 1.0.0–1.0.1 **从未**在任何真机/模拟器上运行；1.0.2 收到一条「Android 16 上点开始检测即退出」的用户反馈，但**没有 `logcat`、没有机型/内核**；1.0.3 的兼容探测/UTF-8/`clock_nanosleep` 加固都是针对该反馈的**推断性修复**，从未复现确认。所以「1.0.3 修好了闪退」这句话**没有证据**。 |
| 已做的验证（可复现） | 双 ABI 零警告编译（15 个 C 文件 / 30 个编译单元 / 0 warning）、`.so` 仅导出 `JNI_OnLoad`、JNI 签名与 dex 对得上、APK v2 签名、`lintVitalRelease` 通过、16 KB `LOAD` 对齐、新增 ID 确实在 `.so` 里、`apksigner` 证书指纹与历史一致 |
| 文档里的数字 | `04-测试矩阵` 是**静态推算**；`02/03` 的"是否可擦除"是分析结论，不是实测；所有「耗时」也未实测 |
| 跨进程 `/proc` | 普通应用读 init/system_server **几乎必然 EACCES**，相关项会 `available=false`（这是"无法判定"，不是"安全"） |
| 判据是否变过 | **变过，6 处**（1.0.2）。1.0.2 的 CHANGELOG 曾误写「判据未改动」，2.0.0-beta 已更正，逐项对照表在 `docs/01` §0.3 |

**所以第一优先级不是加功能，而是拿一台 Android 15/16 设备做基线校准。**

> **这条口径曾经四份文档互相矛盾**（`HANDOVER` 说「从未跑过」、`ROADMAP` 说「真机验证=零」、
> `CHANGELOG` 与 `INDEX` 说「修复了 Android 16 闪退」）。2.0.0-beta 把它们统一成上面这一条。
> 如果你（维护者）其实已经跑过真机，请立刻改正这里并补上设备信息——不要再让文档各说各话。

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

### 2.5 兼容探测层（1.0.3 起，改检测前必须知道）
- 入口：`rasp_jni.c::jni_run_detect` 在**任何**检测之前先 `rasp_stage(&ctx, "probe")` + `rasp_probe_compat(&ctx)`，
  结果决定 `pidfd_open` / `openat2` / `clone3` 能不能用（`rasp_pidfd_enabled()` 等三个门控函数）。
- 为什么需要：部分 ROM 的 seccomp 对较新 syscall 返回 `SECCOMP_RET_TRAP`（`SIGSYS` 直接杀进程），
  不返回 `ENOSYS`。所以「试着调用一下看看」会把整个检测进程带走。
- 做法：`clone(SIGCHLD)` 一个一次性子进程去试（**不共享地址空间、不 malloc、不加锁、不碰 Java**），
  子进程正常退出才采纳结果；被子进程信号杀死就**本次会话永久禁用**对应调用，退化为 `/proc` 路径
  与 `clone(SIGCHLD)`。探测结果落盘 `files/compat_probe.txt`（`pidfd/ openat2/ clone3/ sig=`）。
- 代价（不要忘记）：① 每轮检测多一次 fork + 最长 800 ms 等待，**不计入任何模块预算**，
  最坏总耗时因此是 21.6 s 而不是 20.8 s；② 若子进程因任何原因被信号杀死，三个调用会**一起禁用**，
  `AHK-006` 随之整项不可用（这是保守设计，不是缺陷）。
- 阶段埋点：每个模块执行前把阶段名写进 `files/last_stage`（11 次写文件/轮），崩了下次启动首页出黄色横幅。
  这本身是检测器的**自我痕迹**（fd、写盘），评估「检测器自身被攻击」时要把它算进去。

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
- 密钥：`keystore/aegis-release.jks`（**PKCS12**，别名 `aegis`，口令见本地 `keystore/keystore.properties`（**不入库**），证书 SHA-256 `93:1E:E6:…`）。
- 覆盖升级三条件：`versionCode` 递增、同签名、同包名。换钥 = 换身份，只能卸载重装。
- 应用内「关于 → 更新日志」是 `AboutScreen.kt` 里的字符串常量，**改日志必须改代码重新打包**；
  `CHANGELOG.md` 只是仓库记录，不影响 APK。
- 每次发版要同步：`versionCode/versionName`、`AboutScreen.kt`、`CHANGELOG.md`、`README §8`、`docs/05`、`docs/06`，
  **外加 `INDEX.md`（1.0.2 起新增）与 `HANDOVER.md` 自身的版本行**——1.0.2→1.0.3 就是漏了后者，
  导致交接文档停在 1.0.2。

### 3.10 版本纪律（2.0.0-beta 的教训，比技术坑更贵）
1. **改了判据就要写「判据改了」**。1.0.2 的 CHANGELOG 一边列 6 处判据修改、一边在「未变」里写
   「判据未改动」，`docs/05` 还复述了这句。判据改动会改变同一台设备上的命中结果，它不是「文案」。
   现在 `docs/01` §0.3 有一张固定的变更对照表，**以后每次改判据都必须往这张表里加一行**。
2. **判据文档要和代码同一次提交里改**。`docs/01`–`docs/04` 曾经集体停在 1.0.1 整整两个版本，
   24 万字节的描述全部过期。过期数据比没有数据危险，因为有人会拿它对账。
3. **「是否上过真机」只能有一个答案**。它曾经在 `HANDOVER`／`ROADMAP`／`CHANGELOG`／`INDEX`
   之间有四种说法。现在统一写在 `README` §0 与本文 §1，**改动它必须四处一起改**。
4. **不要用 `suppress` 换「支持」**。`android.suppressUnsupportedCompileSdk=36` 只是关掉 AGP 的
   守卫（AGP 8.7.3 官方上限 35）。能出包 ≠ 受支持。
5. **新阶段要入预算**。1.0.3 加的 `probe` 阶段最长 800 ms，既不在任何模块预算里，也没进文档，
   最坏总耗时从 20.8 s 悄悄变成 21.6 s。
6. **新分配的资源要配对释放**。`MAP_SHARED` 匿名页在 1.0.3 的两处（探测、沙箱）都没 `munmap`，
   每轮检测泄漏一页；这类问题在「点一次就退出」的场景里永远暴露不出来。

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
# 环境
$env:JAVA_HOME='E:\利于民\HMCL(2026.8.16更新)\jdk-17.0.20.1+1'
$env:ANDROID_HOME='C:\Users\Administrator\AppData\Local\Android\Sdk'
$env:ANDROID_SDK_ROOT=$env:ANDROID_HOME

# 构建（走 ASCII 联接，规避中文路径工具问题）
New-Item -ItemType Junction -Path 'E:\aegis-build' -Target 'E:\安卓检测项目' -Force -ErrorAction SilentlyContinue
cd 'E:\aegis-build'
& 'E:\安卓检测项目\.tools\gradle-8.9\bin\gradle.bat' --no-daemon :app-ui:assembleRelease

# 校验
& "$env:ANDROID_HOME\build-tools\35.0.0\apksigner.bat" verify --print-certs `
  'E:\安卓检测项目\app-ui\build\outputs\apk\release\app-ui-release.apk'

# 归档
Copy-Item 'E:\安卓检测项目\app-ui\build\outputs\apk\release\app-ui-release.apk' `
  'E:\安卓检测项目\dist\AegisRASP-<version>-release.apk' -Force
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
| `dist/AegisRASP-2.0.0-beta-release.apk` | **当前可安装产物**（已签名，versionCode 6，targetSdk 36） |
| `dist/AegisRASP-1.0.3-release.apk` | 1.0.3（versionCode 5）：闪退加固 + 阶段诊断 |
| `dist/AegisRASP-1.0.2-release.apk` | 1.0.2（versionCode 4）：API 36 / 16 KB 页对齐 + 6 处判据修正 |
| `dist/AegisRASP-1.0.1-release.apk` | 1.0.1 正式版（versionCode 3），回溯/对比用 |
| `dist/AegisRASP-1.0.1-rc-release.apk` | 1.0.1 的候选版（versionCode 2），回溯/对比用 |
| `dist/AegisRASP-1.0.0-release.apk` | 初版（41 项），回归对比用 |
| `keystore/aegis-release.jks` | 签名私钥，**丢失即无法升级** |
| `rasp-detect-native/src/main/cpp/` | **15 个 C 文件**（引擎 + 9 类检测 + 沙箱 + 打分 + JNI + 兼容探测 `rasp_compat.c`） |
| `app-ui/src/main/java/com/rasp/detect/ui/` | Compose 界面（三标签、组件、导出） |
| `docs/00`–`docs/07` | 设计、检测项、误报、对抗、测试矩阵、构建记录、签名、崩溃排查 |
| `CHANGELOG.md` | 版本变更唯一权威记录 |
| `HANDOVER-2.0.0-beta.md` | **本次会话的交接补充**：当前状态、事件时间线、10 条注意事项、交接清单、项目与维护者评价 |
| `D:\源码与备份\AegisRASP-1.0.1-rc\` | 2 代源码快照（77 文件，versionCode 2，targetSdk 35） |
| `D:\源码与备份\AegisRASP-1.0.2\` | 4 代源码快照（82 文件，versionCode 4，targetSdk 36） |
| `D:\源码与备份\AegisRASP-1.0.3\` | 5 代源码快照（85 文件，versionCode 5，targetSdk 36） |
