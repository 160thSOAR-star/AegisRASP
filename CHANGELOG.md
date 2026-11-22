# 更新日志（CHANGELOG）

本文件是版本变更的**唯一权威记录**。应用内「关于 → 更新日志」展示的是同一份内容的精简版，
但那是编译进 `AboutScreen.kt` 的字符串——**改应用内日志必须改代码并重新打包**，改本文件不会影响 APK。

版本号规则：`MAJOR.MINOR.PATCH`，预发布加 `-alpha` / `-beta` / `-rc`（按成熟度递增）；
每个 APK 的 `versionCode` 必须严格递增，签名与包名不可变（见 `docs/06-签名与迭代.md`）。

---

## [2.0.0-beta] — 2026-11-21 · versionCode 6

> **性质：这不是功能版本，而是「可信度与工程纪律」版本。** 代码层面只改了兼容探测与沙箱的共享页
> 释放和内存屏障（`.so` 约 +240 字节）；**其余全部是文档真值修复**。之所以给 2.0.0 主版本号，
> 是因为此前的文档在「判据到底改没改」「到底上没上过真机」这两个最基本的问题上给出了互相矛盾的
> 答案 —— 这类问题靠 patch 号收不住。

### 修复（按重要度排序，与 `docs/01` §0.3 对应）

1. **统一「真机验证状态」口径（此前四份文档互相矛盾）**：`HANDOVER` §1（「从未在真机/模拟器上跑过」）、
   `ROADMAP`（「真机验证 = 零」）、`CHANGELOG` 1.0.3（「修复 Android 16 闪退」）、`INDEX`（同）四处冲突。
   现统一为：**1.0.0–1.0.1 无任何真机运行记录；1.0.2 收到一条 Android 16 闪退反馈，但未留 `logcat`
   与机型；1.0.3 的兼容探测/UTF-8/`clock_nanosleep` 加固属推断性修复，未复现确认。**
2. **`docs/01`–`docs/04` 按 1.0.2 的判据变更重写**（此前四份共 24 万字节全部停在 1.0.1，仍描述旧判据）：
   - `docs/01` 新增 §0.3「判据变更对照表」，逐项订正 `INJ-005` / `AHK-006` / `KRN-007` / `ZYS-007` /
     `BPF-004` / `MNT-001`，并补充兼容探测层与「probe 不计入预算」；
   - `docs/02` 更新对应豁免面、误报口径与 `INJ-005` 模拟器策略；
   - `docs/03` §2.8 补记 AHK-006 的**假阴性窗口**（含 `2q − q²` 漏检概率量化）；
   - `docs/04` 新增 §6.9「判据变更对预期分数的影响」，更正模拟器典型分与可用项数。
3. **更正 `CHANGELOG` 1.0.2 的「判据未改动」**：实际有 6 处，已在 1.0.2 条目下逐条列出并标注更正。
4. **`HANDOVER` 由 1.0.2 更新到本版**：版本号、可用产物、资产表、外部备份路径、JNI 方法数（5 个）。
5. **`docs/05` 补本版发版记录**，清除残留的 1.0.1 / 1.0.2 安装命令与版本号。
6. **AGP 组合显式化**：`AGP 8.7.3 + compileSdk 36` 依赖 `android.suppressUnsupportedCompileSdk=36`
   绕过官方支持范围（AGP 8.7.3 官方上限为 35）。已在 `README`、`docs/05`、`ROADMAP` 技术债中
   标为**实验性组合**，并修正 `README` 中「Platform 35 / Build-Tools 35.0.0」与「Build-Tools 36.0.0」
   的自相矛盾。
7. **AHK-006 假阴性窗口入档**：1.0.2 只改了代码、没写风险，本版补进 `docs/03` §2.8。
8. **共享页泄漏修复（本版唯一的代码行为改动）**：`rasp_probe_compat` 与 `rasp_check_sandbox` 的
   `MAP_SHARED` 匿名页此前**没有 `munmap`**，每轮检测泄漏一页。新增 `rasp_raw_munmap`
   （同时补齐 x86_64 缺失的 `SYS_MUNMAP = 11`），在两处收尾并置空 `c->shm`；跨进程可见性补
   `__sync_synchronize()`（探测与沙箱两处轮询）。
9. **兼容探测耗时入账**：`probe` 阶段最长约 800 ms 且不计入任何模块预算，最坏总耗时由文档中的
   「20.8 s」更正为 **21.6 s**（`docs/01` 调度模型、`docs/04` §4）。
10. **`INJ-005` 模拟器策略入档**：由「只存在于代码里的硬编码」改为在 `docs/01` §0.3、`docs/02`、
    `docs/04` §2.2、`docs/01` §11 边界中显式声明，并写明代价（模拟器上永久不可用）。

### 未变
- 检测项 **51 项**、白名单 v3、权重（30/10/3）、`0.7^n` 衰减、单强 25 / 反 Hook 85 下限、阈值 20/50、
  各模块预算数值。
- 包名、ABI（arm64-v8a / x86_64）、签名密钥、无 `INTERNET`、`minSdk 30`、`targetSdk 36`、16 KB 页对齐。
- 1.0.2 / 1.0.3 已生效的 6 处判据**行为**（本版只补文档，不再改判据）。

### 已知问题
- **仍无真机基线**。本版没有任何「修好了什么」的结论，只有「记录写对了」的结论。
- `AHK-006` 的假阴性窗口未消除（已记录；修复方向是改用 `mnt_id` 差集判别挂载抖动，见 `ROADMAP` 技术债）。
- `AGP 8.7.3 + compileSdk 36` 仍是 Google 未支持的组合，升级路径见 `ROADMAP` 技术债。
- 1.0.1–1.0.3 的三条已知问题（`INJ-005` 模拟器、`MNT-008/009` 厂商差异、未真机验证）继续有效。

---

## [1.0.3] — 2026-11-21 · versionCode 5

### 修复（Android 16 上点击「开始检测」闪退）
- **兼容性探测先行**：`pidfd_open` / `openat2` / `clone3` 改由**一次性子进程**试调用；
  若子进程被信号杀死（典型为 `SIGSYS`，部分 ROM 的 seccomp 对较新 syscall 返回 TRAP），
  主进程永久禁用对应调用，回退到 `/proc` 路径与 `clone(SIGCHLD)`。
  这消除了「主进程直接撞上 seccomp TRAP 导致闪退」的整类问题。
- **JNI 字符串安全**：证据中的进程名、路径、属性值来自内核，可能不是合法 UTF-8；
  `rb_json_escape` 现在会校验 UTF-8，把非法字节与 4 字节序列替换为 `?`，
  避免 `NewStringUTF` 触发 ART 直接中止（报 `JNI ERROR: input is not valid Modified UTF-8`）。
- **修复 `clock_nanosleep` 参数**：此前少传 `flags` 与 `rem` 两个参数，内核因 `flags` 非法立即返回，
  使沙箱等待变成忙等并可能过早 `SIGKILL` 子进程。
- **clone3 改用探测结果**：不可用时直接用 `clone(SIGCHLD)`，不再盲试。

### 新增（诊断能力）
- **阶段埋点**：每个检测模块执行前把阶段名写入 `files/last_stage`；崩溃后下次启动首页显示黄色横幅，
  指明崩在 `probe/mount/ksu/kernel/bpf/zygisk/inject/security/extra/sandbox/antihook` 哪一步。
- **兼容探测落盘**：`files/compat_probe.txt` 记录 `pidfd/openat2/clone3` 与致命信号编号。
- **Java 崩溃落盘**：未捕获异常写入 `files/last_crash.txt`，下次启动展示前几行堆栈。
- **文档**：新增 `docs/07-崩溃排查.md`（抓日志、读诊断、逐步隔离、反馈清单）。

### 未变
- 51 项检测、白名单 v3、权重与打分模型未改动。
- **但 AHK-006 的可用性改由兼容探测门控**（探测判定 `openat2` 不可用时直接 `available=false`，不再盲试），
  属于可用性判定变更，已记入 `docs/01` §0.3。
- targetSdk 36、16 KB 页对齐、签名密钥与包名不变。

---

## [1.0.2] — 2026-11-21 · versionCode 4

### 兼容（Android 15 起向上）
- **编译与目标 SDK 升级到 Android 16（API 36）**：`compileSdk = 36`、`targetSdk = 36`、Build-Tools 36.0.0；`minSdk` 保持 30。
  已用 `aapt2 dump badging` 复核 `platformBuildVersion=16 / targetSdkVersion:'36'`。
- **16 KB 页对齐**：`Application.mk` 启用 `APP_SUPPORT_FLEXIBLE_PAGE_SIZES := true`，
  `llvm-readelf -l` 确认两个 ABI 的 `libaegisrasp.so` 全部 `LOAD` 段 `Align = 0x4000`，可直接跑在 16 KB 页设备上。
- **预测性返回**：`android:enableOnBackInvokedCallback="true"`；`android:resizeableActivity="true"` 适配大屏/分屏。
- 三态语义与降级逻辑不变：新系统收紧 `/proc` 权限时，相关项仍以 `available=false` 呈现。

### 变更（UI）
- **移除测试页右上角的设置图标**，设置入口只保留底部导航栏的「设置」标签，避免两个入口语义重复。

### 修复（已知问题）
- `INJ-005` 非系统代码映射来源：模拟器（`ro.kernel.qemu` / `ro.boot.qemu` / `ro.hardware=ranchu|goldfish`）下标记为不可用，消除已知误报。
- `AHK-006` openat2 与 openat 一致性：不一致时**复测一次**，两次都不一致才判命中，排除 mountinfo 在两次读取之间抖动造成的假阳性。
- `KRN-007` 返回码语义：`/system/bin/sh` 被 SELinux 拒绝（`EACCES/EPERM`）视为环境限制而非异常。
- `ZYS-007` 线程名：收紧关键词（去掉 `hook`/`inline` 等通用词，改为 `zygisk/lspd/lsposed/riru/magisk/ksud/injected/payload_`）。
- `BPF-004`：init cgroup 不可读时正确标记 `available=false`（此前误报为可用）。
- `MNT-001` 读不到 mountinfo 时，补齐 `MNT-002`~`MNT-006` 的「不可用」占位，保持 51 项覆盖率可见，不再静默缺席。
- `check_errno_semantics` 增加超时熔断检查；native 版本串更新为 `aegis-rasp/1.0.2 (native, api36)`。

### 文档
- 新增 `ROADMAP.md`（发展规划）与 `INDEX.md`（文件目录索引）。
- `README.md`、`docs/05`、`docs/06`、`HANDOVER.md` 同步 1.0.2 与 API 36 口径。

### 未变
- **检测项数量**（仍为 51 项）、白名单 v3 模板与匹配规则、权重（30/10/3）、同类 `0.7^n` 衰减、
  单强 25 下限 / 反 Hook 85 下限、阈值（20/50）、模块预算数值均未改动。
- **⚠️ 更正（2.0.0-beta 重述）**：本条目最初写的是「检测逻辑 51 项与判据均未改动」，**这是错的**。
  1.0.2 实际有 **6 处判据 / 可用性判定变更**：`INJ-005` 模拟器改判不可用、`AHK-006` 改连续两轮复测、
  `KRN-007` 放行 `EACCES`/`EPERM` 并纳入熔断、`ZYS-007` 词表收紧、`BPF-004` 修正 `available`、
  `MNT-001` 补发占位。这些改动**会改变同一台设备上的命中结果**。逐项对照见 `docs/01` §0.3，
  对预期分数的影响见 `docs/04` §6.9，对抗侧代价见 `docs/03` §2.8。
- 签名密钥、包名、ABI（arm64-v8a / x86_64）、无 `INTERNET` 权限。

---

## [1.0.1] — 2026-11-21 · versionCode 3

> **性质：1.0.1-rc 转正式版（RC → Release）。本轮只做版本号、应用内日志、文档同步，
> 以及一处零行为的编译警告清理，不改动任何检测判据。** 检测项（51）、判据、白名单 v3、
> 权重与打分模型、调度预算、权限、包名、ABI、签名密钥全部与 1.0.1-rc 一致。

### 变更
- `versionName`：`1.0.1-rc` → `1.0.1`；`versionCode`：2 → **3**（覆盖升级必须递增，见 `docs/06`）。
- 应用内「关于 → 更新日志」新增 1.0.1 条目（`AboutScreen.kt` 的 `ChangelogRow`），
  原有 1.0.1-rc / 1.0.0 条目保留，作为历史记录。
- **编译洁净度**：删除 `rasp_memory.c::rasp_maps_stats` 中从未使用的局部变量 `r`
  （`-Wunused-variable`，`-O2` 下本就被优化掉，无行为影响），使 `-Wall -Wextra`
  **零警告**成为可复现实事；删除前后 `.so` 字节大小（88,400 / 96,112）与 `.text` 均无变化。
- **`.gitignore`**：补上 `keystore/*.jks` 与 `keystore/keystore.properties`（此前签名私钥未被排除，
  见 `docs/06` §6）。
- 文档同步：本文件、`README.md`（版本与 §8）、`docs/00`（JNI 方法数更正为 5）、
  `docs/01`~`docs/06` 的适用版本标头、`HANDOVER.md` 的当前版本、JNI 方法数与产物清单。

### 未变（重要）
- 检测项 **51 项**（10 类：mount 8 + ksu 5 + kernel 7 + bpf 4 + zygisk 8 + inject 5 +
  selinux 5 + antihook 6 + sandbox 2 + fops 1），等级分布 20 强 / 25 间接 / 6 弱。
- 打分模型：强 30 / 间接 10 / 弱 3、同类 `0.7^n` 衰减、单强下限 25、
  反 Hook（AHK-001..006）下限 85、阈值 20 / 50。
- 白名单 v3 匹配规则与 `whitelist_default.json` 模板。
- 权限（仍无 `INTERNET`）、包名 `com.rasp.detect.aegis`、ABI（arm64-v8a / x86_64）、
  minSdk 30 / targetSdk 35、签名密钥（证书 SHA-256 `93:1E:E6:…:DF:C5:AB`）。

### 发版校验
- 构建：`gradle --no-daemon :app-ui:assembleRelease`（Gradle 8.9 / AGP 8.7.3 / JDK 17 /
  NDK 27.1.12297006 + ndk-build，双 ABI，`-Wall -Wextra` 零警告）。
- 签名：`apksigner verify --print-certs` 通过 **v2** 校验，证书指纹与 1.0.0 / 1.0.1-rc 一致
  → 已装 1.0.0 / 1.0.1-rc 的设备可 `adb install -r` 直接覆盖升级。
- 内容：APK 内含 arm64-v8a 与 x86_64 的 `libaegisrasp.so`、`assets/whitelist_default.json`、
  51 项 ID 与版本串 `aegis-rasp/1.0.1`；`lintVitalRelease` 通过。
- 产物：`dist/AegisRASP-1.0.1-release.apk`；大小与 SHA-256 见 `docs/05` §3 与 `docs/06` §1。

### 已知问题
- 仍**未做真机验证**（当前环境无设备/模拟器），分数区间为静态推算，见 `docs/04`、`docs/05` §5。
- 1.0.1-rc 条目下的三条已知问题（`INJ-005` 模拟器误报、`MNT-008/009` 厂商差异需标定、
  未真机验证）继续有效，本轮未处理——按 `HANDOVER` §1 与 §6，真机基线校准是下一优先级。

---

## [1.0.1-rc] — 2026-11-21 · versionCode 2

### 新增
- **底部三标签导航**：测试（启动默认页）/ 设置 / 关于，替代原先「测试 ↔ 设置」二页切换。
- **关于页**：应用信息（包名、版本、Native 引擎、检测项数、API 下限/目标）、设计思路、
  适用版本与场景、更新日志、开发人员（DEEPSEEK-V4.1-Flash）、合规声明。
- **10 个检测项**（总数 41 → 51）：
  | ID | 名称 | 等级 |
  | --- | --- | --- |
  | MNT-008 | 挂载只读标志与 statfs 一致性 | 间接 |
  | MNT-009 | 挂载设备号与 statx 设备号一致性 | 间接 |
  | KRN-006 | 内核时序自洽性（btime / uptime / BOOTTIME） | 间接 |
  | KRN-007 | syscall 返回码语义异常探针 | 间接 |
  | INJ-005 | 非系统代码映射来源检测 | 间接 |
  | AHK-005 | 函数地址与可执行段一致性 | 强 |
  | AHK-006 | openat2 与 openat 双路径一致性 | 强 |
  | FOPS-001 | 目录枚举与直接访问不一致（procfs 目录过滤） | 强 |
  | ZYS-007 | 异常线程名与线程注入痕迹 | 弱 |
  | ZYS-008 | 系统属性 Java/native 双路径一致性 | 间接 |
- **新的 syscall 封装**：`statfs`、`openat2`（`struct open_how`）、`CLOCK_BOOTTIME`。
- **JNI `readProperty`**：供 ZYS-008 直接读属性区，绕过 Java `SystemProperties`。
- **新类别 `fops`**（文件系统视图一致性），进入打分模型的同类衰减分桶。

### 变更
- 检测项等级分布变为 **20 强 / 25 间接 / 6 弱**。
- 反 Hook 一票否决范围从 AHK-001..004 扩展到 **AHK-001..006**（AHK-005/006 命中即置 `anti_hook_hit`，分数下限 85）。
- 检测顺序加入 `extra` 模块（`security → extra → sandbox → antihook`），模块预算 2500 ms。
- 三个页面的内边距由 `systemBarsPadding` 改为 `statusBarsPadding`，底部 inset 交给导航栏处理。
- 文档全量同步：`00`~`06` 与 `README`（检测项 51 口径、新类别、新观测面、测试矩阵、构建记录、签名记录）。

### 未变
- 打分模型：强 30 / 间接 10 / 弱 3、同类 `0.7^n` 衰减、单强下限 25、反 Hook 下限 85、阈值 20/50。
- 白名单 v3 匹配规则与 `whitelist_default.json` 模板。
- 权限（仍无 `INTERNET`）、包名 `com.rasp.detect.aegis`、ABI（arm64-v8a / x86_64）、签名密钥。

### 已知问题
- 未做真机验证（环境无设备/模拟器）。
- `INJ-005` 在 Android Studio 模拟器上可能因子系统路径产生误报，建议按 ID 豁免。
- `MNT-008` / `MNT-009` 的厂商差异需真机标定。

---

## [1.0.0] — 2026-11-20 · versionCode 1

### 新增
- 首次发布：**41 个检测项**，覆盖挂载命名空间、KernelSU 进程痕迹、内核态间接痕迹、BPF、
  Zygisk/Shamiko/LSPosed/HMA、注入与 ptrace、SELinux/AVB、反 Hook 自校验 8 大类 + clone3 沙箱。
- Native 核心：直调 syscall 引擎（aarch64 `svc #0` / x86_64 `syscall`）、pidfd 读取、
  `clone3` 干净子进程沙箱 + 匿名共享内存回传、多路径交叉校验、证据聚合。
- 加权打分模型 + 白名单 v3 + 报告序列化（JSON）。
- Compose Material3 仪表盘：环形风险表、流式证据卡片、骨架屏、毛玻璃卡片、
  全局图片背景（透明度/磨砂/暗角/颗粒/冷光/模糊）、全屏雪花、报告预览弹窗、
  JSON / Markdown / HTML 导出与分享、设置页、白名单查看。
- 文档：设计理念、检测项清单、误报规避、风险与绕过、测试矩阵、构建与验证记录、签名与迭代。

---

## 发版检查清单

每次发版按顺序确认：

1. `app-ui/build.gradle.kts`：`versionCode += 1`、`versionName` 更新；
2. `AboutScreen.kt` 的 `ChangelogRow(...)`：追加新版本条目（应用内展示）；
3. 本文件追加条目；`README.md` §8 摘要同步；`docs/05` 记录构建校验；`docs/06` 更新版本与 APK 哈希；
4. `./gradlew :app-ui:assembleRelease` → `apksigner verify --print-certs` 校验指纹；
5. 产物归档到 `dist/`，并按需同步备份目录。
