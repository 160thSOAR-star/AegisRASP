# Aegis RASP —— Android 15 / CloreOS15 KernelSU 本地运行时检测

一套面向 **Android 15（API 35）** 的 KernelSU 隐藏环境**本地**检测方案：**51 个检测项**、纯非 Root 用户态执行、Native（C-bionic）核心 + Jetpack Compose Material3 仪表盘。

当前版本：**1.0.1**（versionCode 3）

- **只做痕迹检测与证据采集**：不实现任何绕过、攻击或修改 KernelSU / Root 环境的行为。
- **全部本地**：不发起任何网络请求，不使用 SafetyNet / Play Integrity 等远程校验，Manifest 中未申请 `INTERNET` 权限。
- **不需要 Root**：全部检测运行在普通 `untrusted_app` 进程及其 `clone3` 子进程沙箱内。

---

## 1. 产物

| 文件 | 说明 |
| --- | --- |
| **Releases 页的 `AegisRASP-1.0.1-release.apk`** | **当前发布版**：已签名 Release APK，2.30 MB（2,414,555 字节），SHA-256 `B98ACACE…38D4B984` |
| `app-ui/build/outputs/apk/release/app-ui-release.apk` | 本地构建产物（`./gradlew :app-ui:assembleRelease`） |
| `CHANGELOG.md` | **版本变更的唯一权威记录**（含发版检查清单） |
| `INDEX.md` | **文件目录索引**：按"要找什么"列出文档、源码、构建配置 |
| `HANDOVER.md` | 交接说明：状态、设计思路、踩坑点、禁止事项、开工命令 |
| `docs/00-设计理念.md` | 为什么这样设计：观测模型、五条准则、打分哲学、UI 与工程取舍 |
| `docs/01-检测项清单.md` | 51 个检测项的原理、实现、痕迹特征、Momo 为何检测不到 |
| `docs/02-误报规避与白名单.md` | 分级白名单、逐项误报场景与过滤规则 |
| `docs/03-风险与绕过分析.md` | 每类的未来绕过可能、兜底思路、本质性痕迹判定 |
| `docs/04-测试矩阵.md` | 8 类环境下的预期分数、命中证据、耗时 |
| `docs/05-构建与验证记录.md` | 构建环境、命令、已完成的校验、未做真机验证的项 |
| `docs/06-签名与迭代.md` | 证书指纹、版本号规则、覆盖升级与重签流程（口令不入库） |

> APK 不作为源码提交，只在 **Releases** 页提供下载（体积大且每次发版都会让仓库历史翻倍）。

安装：从 Releases 下载 `AegisRASP-1.0.1-release.apk` 后 `adb install -r AegisRASP-1.0.1-release.apk`

---

## 2. 界面结构（1.0.1 起）

底部三标签导航，启动默认「测试」页：

| 标签 | 内容 |
| --- | --- |
| **测试** | 环形风险仪表盘、实时证据流、进度与骨架屏、操作按钮（检测/停止/预览报告/导出/分享） |
| **设置** | 检测调度、检测项开关（51 项）、自定义权重、背景系统、雪花动画、主题、白名单查看、缓存清理 |
| **关于** | 应用信息、设计思路、适用版本与场景、更新日志、开发人员、合规声明 |

---

## 3. 架构

```
app-ui (Compose UI，底部三标签)
   │  StateFlow / Flow
   ▼
RaspViewModel ──► RaspEngine ──► JavaProbes (包列表多路径 / Binder 一致性 / 属性双路径)
   │                                │ submitEvidence(json)
   │                                ▼
   └────────── 证据流式回调 ◄── rasp_jni.c（JNI 接口层）
                                 │
                                 ▼
              rasp-detect-native（C11 / bionic / API 35）
              ├─ rasp_syscall.c        直调 syscall 引擎（svc #0 / syscall，绕过 libc 包装）
              ├─ rasp_util.c           有界进程枚举、pidfd 读取、证据聚合、JSON 序列化
              ├─ rasp_memory.c         /proc/self/maps 解析、函数序言完整性
              ├─ rasp_sandbox.c        clone3 干净子进程 + 匿名共享内存回传
              ├─ rasp_checks_mount.c   MNT-001..006
              ├─ rasp_checks_ksu.c     KSU-001..005
              ├─ rasp_checks_kernel.c  KRN-001..005 + BPF-001..004
              ├─ rasp_checks_zygisk.c  ZYS-001..004（ZYS-005/006/008 由 Java 层补充）
              ├─ rasp_checks_inject.c  INJ-001..004
              ├─ rasp_checks_security.c SEL-001..005
              ├─ rasp_checks_extra.c   MNT-008/009、KRN-006/007、INJ-005、AHK-005/006、FOPS-001、ZYS-007
              ├─ rasp_checks_antihook.c AHK-001..004
              ├─ rasp_score.c          加权打分聚合 + 报告序列化
              └─ rasp_jni.c            RegisterNatives，符号不导出
```

关键设计：

1. **直调 syscall 引擎**：`rasp_syscall.h` 用内联汇编（aarch64 `svc #0`、x86_64 `syscall`）实现 openat/openat2/read/close/statx/statfs/getdents64/pidfd_open/clone3/memfd_create 等，与 libc 路径交叉校验（AHK-002 / AHK-006）。
2. **干净检测沙箱**：`clone3(flags=SIGCHLD)` 创建不共享地址空间的新进程，子进程用直调 syscall 重读挂载视图与文件元信息，经 `MAP_SHARED|MAP_ANONYMOUS` 回传，父子哈希不一致即说明父进程视图被 Hook 伪造（MNT-007）。
3. **跨视图交叉校验**：`pidfd_open` + `openat(pidfd, "mountinfo")` 读取 init / system_server 的视图（受限时标记 `available=false`）；本进程内用 `statx` 的 `stx_mnt_id`、`stx_dev`、`statfs` 的 `ST_RDONLY` 与 mountinfo 做物理自洽性校验（MNT-001/008/009）。
4. **多路径一致性**：同一份信息分别走 libc、直调 syscall、pidfd、`/proc/self/root`、`openat2` 路径，结果不一致即判定 Hook 篡改（AHK-002 / AHK-006 / MNT-003 / MNT-006）。
5. **目录级过滤检测**：`getdents64` 枚举与"按名字直接访问"结果不一致，说明 procfs 被做了目录过滤（FOPS-001）——这是只 hook `readdir` 的隐藏套件最容易漏的破绽。

---

## 4. 目录结构

```
E:\安卓检测项目
├─ settings.gradle.kts / build.gradle.kts / gradle.properties
├─ rasp-detect-native/          # Native 检测核心 + Kotlin SDK（无 UI）
│  ├─ src/main/cpp/             # 14 个 C 文件 + Android.mk / Application.mk / CMakeLists.txt
│  ├─ src/main/java/com/rasp/detect/  # RaspNative / RaspEngine / 数据模型 / 白名单 / 报告导出
│  └─ src/main/assets/whitelist_default.json
├─ app-ui/                      # Compose Material3 UI 层（不含任何检测逻辑）
│  └─ src/main/java/com/rasp/detect/ui/
│     ├─ MainActivity.kt  RaspViewModel.kt  UiState.kt
│     ├─ components/  RiskGauge / GlassCard / SnowfallLayer / EvidenceCard / ReportSheet / Background
│     ├─ screens/     DashboardScreen / SettingsScreen / AboutScreen / BackgroundPanel
│     ├─ data/        SettingsRepository（DataStore）
│     └─ export/      ExportManager（JSON / Markdown / HTML + 分享）
├─ docs/                        # 00 设计理念、01 检测项、02 误报、03 风险、04 测试矩阵、05 构建记录、06 签名
├─ keystore/                    # 只有 README：签名私钥与口令不入库
└─ dist/                        # 本地交付 APK，不入库（走 Releases 分发）
```

---

## 5. 构建

环境：JDK 17、Android SDK Platform 35、Build-Tools 35.0.0、NDK 27.1.12297006（ndk-build）、Gradle 8.9。

```bash
# 1. 本地 SDK 路径
echo sdk.dir=C\:\\Users\\<you>\\AppData\\Local\\Android\\Sdk > local.properties

# 2. 构建（首次会下载依赖）
./gradlew :app-ui:assembleRelease

# 3. 或先编译 native 单模块
./gradlew :rasp-detect-native:assembleRelease
```

> 工作区路径含中文时，AGP 默认会拒绝构建；本项目已在 `gradle.properties` 设置 `android.overridePathCheck=true` 并验证可用。
> native 构建使用 NDK 自带 `ndk-build`（本机 CMake 在 ABI 探测阶段崩溃）；`CMakeLists.txt` 仍随源码提供。

---

## 6. 打分模型

| 证据等级 | 单条权重 | 说明 |
| --- | --- | --- |
| 强证据 | 30 | 单条即可把风险拉至「可疑」（下限 25） |
| 间接证据 | 10 | 需组合判断 |
| 弱线索 | 3 | 不单独参与判定 |

- 同类（category + grade）叠加按 `0.7^n` 衰减；
- 白名单命中即豁免（v3 规则：ID 精确匹配 / 片段 ≥10 字节且具体）；
- 只有 1 条弱线索时得分再减半；
- **反 Hook 自校验命中（AHK-001..006）直接把分数下限抬到 85**；
- 阈值：`0-20 安全`、`21-50 可疑`、`51-100 高风险`；
- 支持逐项自定义权重与逐项开关（51 项均可单独关闭）。

---

## 7. 使用

1. 打开应用默认进入「测试」页 → 点击「开始检测」，环表实时增长，证据卡片流式出现（可展开看原始 JSON）；
2. 「预览报告」查看完整报告，可导出 JSON / Markdown / HTML 或直接分享；
3. 「设置」页可调：检测项开关、自定义权重、背景图片与质感、雪花动画、主题、白名单查看、缓存清理；
4. 「关于」页包含应用信息、设计思路、适用版本、更新日志与开发人员。

---

## 8. 更新日志

> 完整变更以仓库根目录 [CHANGELOG.md](CHANGELOG.md) 为准；应用内「关于 → 更新日志」是其精简版。

### 1.0.1（2026-11-21，versionCode 3）

- **发版性质**：1.0.1-rc **转正式版**；检测项（51）、判据、白名单 v3、权重与打分模型、调度预算**均未变更**。
- **编译洁净度**：删除 `rasp_memory.c` 中一处从未使用的局部变量（`-Wunused-variable`，无行为影响），
  使双 ABI `-Wall -Wextra` **零警告**可复现；`.so` 字节大小与 `.text` 均未变。
- **安全**：`.gitignore` 补上 `keystore/*.jks`，避免签名私钥被误提交。
- **版本号**：`versionCode` 2 → 3，`versionName` `1.0.1-rc` → `1.0.1`。
- **应用内日志**：「关于 → 更新日志」新增 1.0.1 条目，保留 1.0.1-rc / 1.0.0 历史条目。
- **校验**：v2 签名与证书指纹（与 1.0.0 同一密钥）、双 ABI `.so`、51 项 ID、JNI 契约、`lintVitalRelease` 全部通过。
- **产物**：`AegisRASP-1.0.1-release.apk`（Releases 附件），SHA-256 `B98ACACE…38D4B984`（完整值见 `docs/05` §3、`docs/06` §1）。
- **覆盖升级**：与 1.0.0 / 1.0.1-rc 同一签名，已装旧版可直接 `adb install -r`。

### 1.0.1-rc（2026-11-21，versionCode 2）

- **UI**：新增底部三标签导航（测试 / 设置 / 关于），测试页为启动默认页；新增「关于」页。
- **检测**：新增 10 个检测项，总数 41 → 51：
  MNT-008 挂载只读标志与 statfs 一致性、MNT-009 挂载设备号与 statx 设备号一致性、
  KRN-006 内核时序自洽性、KRN-007 syscall 返回码语义异常探针、
  INJ-005 非系统代码映射来源、AHK-005 函数地址与可执行段一致性、AHK-006 openat2 与 openat 双路径一致性、
  FOPS-001 目录枚举与直接访问不一致、ZYS-007 异常线程名、ZYS-008 系统属性 Java/native 双路径一致性。
- **新增 syscall 封装**：`statfs`、`openat2`、`CLOCK_BOOTTIME`。
- **文档**：00-06 与 README 全量同步。

### 1.0.0（2026-11-20，versionCode 1）

- 首次发布：41 个检测项，Native 直调 syscall + clone3 沙箱 + 加权打分。
- Compose Material3 仪表盘：环形风险表、流式证据、毛玻璃卡片、全局背景与雪花。
- 支持 JSON / Markdown / HTML 报告导出与分享。

---

## 9. 已知限制（重要）

- **跨进程 `/proc` 读取受 SELinux + ptrace scope 限制**：普通应用读取 init / system_server 的 `mountinfo`、`status`、`root/...` 通常返回 `EACCES`。此时对应检测项以 `available=false` + `error` 标注，**这是「无法判定」而不是「安全」**。
- `ZYS-006` 依赖非 SDK 接口（ServiceManager / IPackageManager），被隐藏 API 策略拦截时降级为 `unavailable`。
- `AHK-006` 依赖 `openat2`（内核 5.6+），不可用时标记 `available=false`。
- `KRN-005`、`BPF-002`、`SEL-002` 在部分设备不可读，同样只做不可用标注。
- 隐藏套件若同时 Hook 本进程的 `openat` 且对沙箱子进程做同样的伪造，单机检测的置信度会下降；此时以 AHK 的代码段/调用路径交叉校验为最后防线。

---

## 10. 合规声明

本项目的全部代码用于**设备本地痕迹检测与证据采集**，不包含任何绕过、攻击、提权或修改 KernelSU / Magisk / LSPosed 环境的功能；不采集、不上传任何用户数据；不进行任何远程校验。

---

## 11. 许可证

MIT License，见 [`LICENSE`](LICENSE)。可自由使用、修改、商用与再分发，保留版权声明即可。

签名私钥、口令与发布用 APK 不在本仓库内（见 `keystore/README.md` 与 `.gitignore`）；从 Releases 下载的安装包由项目维护者用同一密钥签名，可用证书指纹核对。
