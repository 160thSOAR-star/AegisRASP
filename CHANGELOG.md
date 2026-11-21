# 更新日志（CHANGELOG）

本文件是版本变更的**唯一权威记录**。应用内「关于 → 更新日志」展示的是同一份内容的精简版，
但那是编译进 `AboutScreen.kt` 的字符串——**改应用内日志必须改代码并重新打包**，改本文件不会影响 APK。

版本号规则：`MAJOR.MINOR.PATCH`，预发布加 `-rc`（release candidate）；
每个 APK 的 `versionCode` 必须严格递增，签名与包名不可变（见 `docs/06-签名与迭代.md`）。

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
