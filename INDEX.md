# 文件索引（INDEX）

> 本表按"你要找什么"组织。路径相对工程根目录 `E:\安卓检测项目`。
> 行数为实际统计（2026-11-21），`—` 表示二进制/无需统计。

## 0. 一眼看懂

| 项 | 值 |
| --- | --- |
| 当前版本 | **2.0.0-beta**（versionCode **6**，targetSdk 36；可信度/工程纪律版，检测行为未变） |
| 当前交付 APK | `dist/AegisRASP-2.0.0-beta-release.apk`（2,430,987 B，SHA-256 `CCFA3A26…C0A25954`） |
| 包名 / ABI / SDK | `com.rasp.detect.aegis` / arm64-v8a、x86_64 / minSdk 30、targetSdk 36 |
| 检测项 | 51 项（20 强 / 25 间接 / 6 弱） |
| native 对齐 | 16 KB 页（全部 `LOAD` 段 `Align=0x4000`） |
| 签名 | 同一密钥：证书 SHA-256 `93:1E:E6:…:DF:C5:AB`（1.0.0 → 2.0.0-beta 全系可互相覆盖升级） |

---

## 1. 交付产物 `dist/`

| 文件 | 大小 | SHA-256（前缀） | 用途 |
| --- | --- | --- | --- |
| `AegisRASP-2.0.0-beta-release.apk` | 2,430,987 B | `CCFA3A26…C0A25954` | **当前交付**（versionCode 6，v2.0.0-beta） |
| `AegisRASP-1.0.3-release.apk` | 2,430,987 B | `8C5B948E…3839D54` | 1.0.3（v5，闪退加固 + 阶段诊断） |
| `AegisRASP-1.0.2-release.apk` | 2,398,219 B | `EB92F1D4…F8C0D1DE8` | 1.0.2（v4，targetSdk 36） |
| `AegisRASP-1.0.1-release.apk` | 2,414,555 B | `B98ACACE…38D4B984` | 1.0.1 正式版（v3） |
| `AegisRASP-1.0.1-rc-release.apk` | 2,414,559 B | `4D393C63…01A2D706` | 候选版（v2） |
| `AegisRASP-1.0.0-release.apk` | 2,349,019 B | `41A6C95C…587F45AF` | 首版（v1，41 项） |

> 所有 APK 同一签名。安装：`adb install -r dist\AegisRASP-2.0.0-beta-release.apk`

---

## 2. 文档与根级说明

### 2.1 根目录

| 文件 | 行数 | 作用 |
| --- | --- | --- |
| `README.md` | 204 | 总览：产物、界面结构、架构、构建、打分模型、使用、更新日志、限制 |
| `CHANGELOG.md` | 120 | **版本变更唯一权威记录** + 发版检查清单 |
| `HANDOVER.md` | 257 | 交接说明：状态、设计思路、9 类踩坑点、版本纪律、禁止事项、开工命令 |
| `HANDOVER-2.0.0-beta.md` | 375 | **本次会话交接补充**：当前状态、事件时间线、10 条注意事项、交接清单、项目与维护者评价 |
| `INDEX.md` | 本文件 | 文件目录索引 |
| `ROADMAP.md` | 173 | 发展规划：版本路线、技术债、KPI、风险登记 |

### 2.2 `docs/`

| 文件 | 行数 | 内容 |
| --- | --- | --- |
| `00-设计理念.md` | 357 | 观测模型、五条准则、架构信任分层、打分哲学、UI 与工程取舍、反模式、演进 |
| `01-检测项清单.md` | 620 | **51 个检测项**逐条：等级 / 原理 / 实现 / 痕迹 / Momo 为何检测不到 / 开销 / 限制 |
| `02-误报规避与白名单.md` | 460 | 三级白名单、v3 匹配规则、51 行逐项误报表、模板 JSON |
| `03-风险与绕过分析.md` | 377 | 8 大类 + 沙箱 + 文件系统视图的绕过路径与兜底、可擦除性判定、二阶对抗 |
| `04-测试矩阵.md` | 452 | 8 场景预期分数/命中 ID/耗时、51 口径项数核算、手算示例、回归清单 |
| `05-构建与验证记录.md` | 119 | 环境、命令、产物、已执行校验、未做真机验证的项 |
| `06-签名与迭代.md` | 184 | 密钥/口令/指纹、versionCode 规则、覆盖升级、重签、生产化建议 |

---

## 3. Native 核心 `rasp-detect-native/src/main/cpp/`

### 3.1 引擎与基础设施

| 文件 | 行数 | 作用 |
| --- | --- | --- |
| `rasp_core.h` | 162 | 证据结构、上下文、各模块入口声明、工具函数原型 |
| `rasp_syscall.h` | 356 | 直调 syscall 引擎（aarch64 `svc #0` / x86_64 `syscall`）、`statx`/`statfs`/`open_how`/`clone_args` 结构 |
| `rasp_syscall.c` | 201 | 上述封装的实现，统一 errno 处理 |
| `rasp_util.c` | 633 | 时间/哈希、JSON 缓冲、文件与 procfs 读取（pidfd 优先）、有界进程枚举、白名单解析、证据聚合 |
| `rasp_memory.c` | 236 | `/proc/self/maps` 解析、映射统计、函数序言完整性（含跳转目标校验） |
| `rasp_memory.h` | 35 | maps 结构体与统计接口 |
| `rasp_sandbox.c` | 259 | `clone3` 干净子进程 + 匿名共享内存回传（MNT-007 / SBX-001） |
| `rasp_score.c` | 315 | 加权打分（30/10/3、`0.7^n`、下限 25/85）、白名单豁免、报告序列化 |
| `rasp_jni.c` | 297 | `RegisterNatives`、证据流式回调、`readProperty`、反 Hook 表校验、JNI_OnLoad |

### 3.2 检测模块

| 文件 | 行数 | 覆盖检测项 |
| --- | --- | --- |
| `rasp_checks_mount.c` | 474 | MNT-001 ~ MNT-006 |
| `rasp_checks_ksu.c` | 398 | KSU-001 ~ KSU-005 |
| `rasp_checks_kernel.c` | 565 | KRN-001 ~ KRN-005、BPF-001 ~ BPF-004 |
| `rasp_checks_zygisk.c` | 265 | ZYS-001 ~ ZYS-004（ZYS-005/006/008 由 Java 层补充、ZYS-007 在 extra） |
| `rasp_checks_inject.c` | 237 | INJ-001 ~ INJ-004 |
| `rasp_checks_security.c` | 315 | SEL-001 ~ SEL-005 |
| `rasp_checks_extra.c` | 671 | **1.0.1 新增**：MNT-008/009、KRN-006/007、INJ-005、AHK-005/006、FOPS-001、ZYS-007 |
| `rasp_checks_antihook.c` | 264 | AHK-001 ~ AHK-004 |

### 3.3 构建与资源

| 文件 | 行数 | 作用 |
| --- | --- | --- |
| `Android.mk` | 28 | **实际使用的 ndk-build 脚本**（CMake 在本机会崩） |
| `Application.mk` | 7 | `APP_PLATFORM=android-30`、`APP_ABI`、`APP_STL=none` |
| `CMakeLists.txt` | — | 备用 CMake 构建（当前未参与构建） |
| `../assets/whitelist_default.json` | 61 | 白名单模板 v3（mounts / processes / properties / kernel / oem / mountPaths） |

---

## 4. Kotlin SDK `rasp-detect-native/src/main/java/com/rasp/detect/`

| 文件 | 行数 | 作用 |
| --- | --- | --- |
| `RaspNative.kt` | 56 | JNI 门面：`runDetect` / `submitEvidence` / `cancelDetect` / `readProperty` / `nativeVersion` |
| `RaspModels.kt` | 246 | 证据、报告、配置数据类；与 native JSON 一一对应 |
| `RaspEngine.kt` | 66 | 检测调度：Java 探针 → 白名单 → native 检测 → 报告 |
| `JavaProbes.kt` | 176 | ZYS-005 包列表多路径、ZYS-006 binder 直查、ZYS-008 属性双路径 |
| `CheckCatalog.kt` | 91 | **51 项静态元数据**（ID/名称/类别/等级/开销），设置页与关于页的数据源 |
| `Whitelist.kt` | 79 | 白名单模型、assets 加载、合并 |
| `ReportExporter.kt` | 181 | JSON / Markdown / HTML 报告生成 |

---

## 5. Compose UI `app-ui/src/main/java/com/rasp/detect/ui/`

### 5.1 入口与状态

| 文件 | 行数 | 作用 |
| --- | --- | --- |
| `MainActivity.kt` | 205 | 入口、`AegisTab`（测试/设置/关于）与底部导航、导出/分享动作 |
| `RaspViewModel.kt` | 143 | `StateFlow` 状态、检测任务、设置透传 |
| `UiState.kt` | 56 | `RaspUiState`、`DetectPhase`、`AppSettings` |
| `data/SettingsRepository.kt` | 119 | DataStore 持久化（背景/雪花/主题/检测配置） |
| `export/ExportManager.kt` | 72 | 报告落盘、FileProvider 分享、剪贴板、缓存清理 |

### 5.2 页面 `screens/`

| 文件 | 行数 | 作用 |
| --- | --- | --- |
| `DashboardScreen.kt` | 414 | 测试页：仪表盘、进度、证据列表、操作按钮 |
| `SettingsScreen.kt` | 449 | 设置页：调度、51 项开关、权重、主题、白名单、缓存 |
| `AboutScreen.kt` | 319 | 关于页：应用信息、设计思路、适用版本、更新日志、开发人员 |
| `BackgroundPanel.kt` | 224 | 背景设置面板（导入图片、透明度/磨砂/暗角/颗粒/模糊）+ 滑块/开关组件 |

### 5.3 组件 `components/`

| 文件 | 行数 | 作用 |
| --- | --- | --- |
| `RiskGauge.kt` | 180 | 环形仪表盘（270°、分段渐变、平滑动画） |
| `Glass.kt` | 137 | 毛玻璃卡片、标签、分区标题、信息行 |
| `SnowfallLayer.kt` | 173 | Canvas 雪花（密度/大小/速度/透明度、低端降采样、不可见暂停） |
| `Background.kt` | 227 | 背景图层（图片/冷光/磨砂/暗角/颗粒/模糊）、图片采样与持久化 |
| `EvidenceCard.kt` | 232 | 可展开证据卡片（原始 JSON/错误/时间） |
| `ReportSheet.kt` | 208 | 报告预览底部弹窗 + 导出入口 |
| `Skeleton.kt` | 27 | 骨架屏呼吸动画 |
| `theme/Theme.kt` | 119 | 深色三色体系、字体、强调色主题 |

---

## 6. 资源与清单

| 文件 | 行数 | 作用 |
| --- | --- | --- |
| `app-ui/src/main/AndroidManifest.xml` | 42 | 启动 Activity、FileProvider；**无 INTERNET 权限** |
| `app-ui/src/main/res/values/strings.xml` | 20 | 文案 |
| `app-ui/src/main/res/values/colors.xml` | 9 | 基础色 |
| `app-ui/src/main/res/values/themes.xml` | 12 | 窗口主题（深色、透明状态栏） |
| `app-ui/src/main/res/xml/file_paths.xml` | 7 | FileProvider 路径（cache/exports） |
| `app-ui/src/main/res/drawable/ic_launcher.xml` | 29 | 矢量图标（盾牌 + 对勾） |
| `rasp-detect-native/src/main/AndroidManifest.xml` | 4 | 库清单（无权限、无组件） |

---

## 7. 构建配置

| 文件 | 行数 | 作用 |
| --- | --- | --- |
| `settings.gradle.kts` | 26 | 模块声明、阿里云镜像优先 + 官方源兜底 |
| `build.gradle.kts` | 8 | 插件版本（AGP 8.7.3 / Kotlin 2.0.21 / Compose 插件） |
| `gradle.properties` | 11 | JVM 参数、AndroidX、**`android.overridePathCheck=true`** |
| `local.properties` | 2 | SDK 路径（不入库） |
| `app-ui/build.gradle.kts` | 91 | 应用模块：versionCode/versionName、签名、R8、Compose、依赖 |
| `rasp-detect-native/build.gradle.kts` | 65 | 库模块：`ndkBuild` 接入、abiFilters、编译参数 |
| `app-ui/proguard-rules.pro` / `rasp-detect-native/consumer-rules.pro` | 6 / 6 | 保留 `com.rasp.detect.**` 与 JNI 相关签名 |
| `gradlew` / `gradlew.bat` / `gradle/wrapper/*` | 253 / 95 / 8 | Wrapper（`distributionUrl` 指向腾讯云镜像） |
| `.gitignore` | — | 排除 build/.gradle/.tools/local.properties |

---

## 8. 签名与工具链

| 路径 | 说明 |
| --- | --- |
| `keystore/aegis-release.jks` | 签名私钥（PKCS12，别名 `aegis`）；**不入库**，口令由本地 `keystore/keystore.properties` 提供（文件 SHA-256 `375A021F…915403`） |
| `.tools/gradle-8.9/` | 本机 Gradle 8.9（wrapper 也可用；`.tools` 另含 ~1.3 GB 下载缓存） |
| `C:\Users\Administrator\AppData\Local\Android\Sdk` | SDK：platform-35、build-tools 35.0.0、NDK 27.1.12297006、platform-tools 37.0.1 |
| `E:\aegis-build` | 指向本工程的 ASCII 目录联接，用于规避中文路径工具问题（构建时 `cd` 到这里） |

---

## 9. 外部备份

| 路径 | 状态 |
| --- | --- |
| `D:\源码与备份\AegisRASP-1.0.1-rc\` | 2 代源码快照（77 文件 / 5.2 MB，versionCode 2、targetSdk 35） |
| `D:\源码与备份\AegisRASP-1.0.2\` | 4 代源码快照（82 文件 / 9.88 MB，versionCode 4、targetSdk 36） |
| `D:\源码与备份\AegisRASP-1.0.3\` | 5 代源码快照（85 文件 / 12.22 MB，versionCode 5、targetSdk 36，即当前代） |
| `D:\源码与备份\README.md` | 备份索引：代际对应、哈希、重建步骤、安全提醒 |
| 加密移动设备 | 用户已把 C 盘备份迁出，本机不再保证存在 |

---

## 10. 常见改动 → 需要动哪些文件

| 任务 | 必改 | 别忘了 |
| --- | --- | --- |
| 新增一个检测项 | `rasp_checks_*.c`（新函数+`rasp_emit`）、`rasp_core.h`（如新增模块）、`Android.mk`/`CMakeLists.txt`（若新增 .c）、`CheckCatalog.kt`、`docs/01` | 等级/置信度要和 `docs/02` 的误报表一致；跑一遍 `docs/04` 的回归 |
| 改 UI | `app-ui/.../screens/*` 或 `components/*` | 不要把检测逻辑写进 Compose；改完确认 51 项仍能流式渲染 |
| 改白名单 | `whitelist_default.json` + `rasp_score.c` 的匹配规则（改规则要三思） | 用新片段去 51 项 raw 里搜，确认只豁免预期 ID |
| 发版 | `app-ui/build.gradle.kts`（versionCode+1）、`AboutScreen.kt`（应用内日志）、`CHANGELOG.md`、`README §8`、`docs/05`、`docs/06` | 签名/包名不可变；产物归档到 `dist/` |
| 排查误报 | `docs/02`（逐项误报表）、对应 C 模块的阈值 | 优先怀疑 ART/JIT、bionic ifunc、厂商差异 |

---

## 11. 版本状态说明（重要）

- 源码、`CHANGELOG.md`、`README.md`、`HANDOVER.md`、`HANDOVER-2.0.0-beta.md`、`ROADMAP.md`、`docs/05`、`docs/06`、`AboutScreen.kt` 均为 **2.0.0-beta / versionCode 6 / targetSdk 36**，状态一致。
- 1.0.3 相对 1.0.2：检测逻辑未变，改动集中在 **闪退修复**（系统调用兼容性探测、UTF-8 校验、沙箱等待修复）与 **崩溃诊断能力**（阶段埋点、兼容探测落盘、Java 崩溃落盘）。
- **外部备份现状**：`D:\源码与备份\` 保存 2 代（1.0.1-rc）、4 代（1.0.2）、5 代（1.0.3）的完整源码快照，各一独立文件夹，并附 `manifests\*.sha256` 逐文件校验清单；
  原 `C:\战争雷霆第三方\重要文件\` 下的 2 代快照已校验一致后迁移至 D 盘，C 盘原件已删除。
  1 代（1.0.0）与 3 代（1.0.1）只保留 APK，源码未单独归档。
- 上表行数为 2026-11-21 的一次性统计，文档更新后会小幅漂移；以实际文件为准。
