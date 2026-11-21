package com.rasp.detect.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.SystemUpdate
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.rasp.detect.CheckCatalog
import com.rasp.detect.RaspNative
import com.rasp.detect.ui.BuildConfig
import com.rasp.detect.ui.components.GlassCard
import com.rasp.detect.ui.components.InfoRow
import com.rasp.detect.ui.components.SectionHeader
import com.rasp.detect.ui.components.TagChip
import com.rasp.detect.ui.theme.ColdBlue
import com.rasp.detect.ui.theme.Cyan
import com.rasp.detect.ui.theme.TextMuted

/** 关于页：应用信息、设计思路、适用版本、更新日志、开发人员。 */
@Composable
fun AboutScreen(modifier: Modifier = Modifier) {
    val versionName = BuildConfig.VERSION_NAME
    val nativeVersion = RaspNative.versionOrNull() ?: "未加载"

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .statusBarsPadding()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 10.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    imageVector = Icons.Filled.Info,
                    contentDescription = null,
                    tint = Cyan,
                    modifier = Modifier.size(22.dp)
                )
                Text(
                    text = "关于",
                    style = MaterialTheme.typography.headlineSmall,
                    modifier = Modifier.padding(start = 8.dp)
                )
            }
        }

        // ---------------- 应用身份 ----------------
        item {
            GlassCard(modifier = Modifier.fillMaxWidth(), corner = 24.dp) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    androidx.compose.foundation.layout.Box(
                        modifier = Modifier
                            .size(48.dp)
                            .clip(RoundedCornerShape(16.dp))
                            .background(
                                Brush.linearGradient(
                                    listOf(Cyan.copy(alpha = 0.24f), ColdBlue.copy(alpha = 0.18f))
                                )
                            ),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = Icons.Filled.Security,
                            contentDescription = null,
                            tint = Cyan,
                            modifier = Modifier.size(26.dp)
                        )
                    }
                    Column(Modifier.padding(start = 14.dp)) {
                        Text(
                            text = "Aegis RASP",
                            style = MaterialTheme.typography.headlineSmall,
                            fontWeight = FontWeight.Bold
                        )
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            TagChip(text = "v$versionName", color = Cyan)
                            Text(
                                text = "  KernelSU 运行时检测",
                                style = MaterialTheme.typography.labelSmall,
                                color = TextMuted
                            )
                        }
                    }
                }
                Column(Modifier.padding(top = 12.dp)) {
                    InfoRow("包名", BuildConfig.APPLICATION_ID)
                    InfoRow("版本", "$versionName（versionCode ${BuildConfig.VERSION_CODE}）")
                    InfoRow("Native 引擎", nativeVersion)
                    InfoRow("检测项", "${CheckCatalog.total} 项 · 8 大类 + 沙箱 + 文件系统视图")
                    InfoRow("最低系统", "Android 11（API 30）")
                    InfoRow("目标系统", "Android 15（API 35）")
                    InfoRow("权限", "无（未申请 INTERNET / 存储 / Root 相关权限）")
                }
            }
        }

        // ---------------- 设计思路 ----------------
        item {
            GlassCard(modifier = Modifier.fillMaxWidth(), corner = 22.dp) {
                SectionHeader(title = "设计思路")
                Text(
                    text = "不检测「是否 Root」，而检测「隐藏行为是否在系统各处留下了互相矛盾的说法」。",
                    style = MaterialTheme.typography.bodyMedium,
                    color = Color(0xFFBFD6FF)
                )
                Spacer(Modifier.height(8.dp))
                listOf(
                    "物理自洽优先：statx 的挂载 ID 必须在 mountinfo 里，status 的 Uid 必须等于 getuid()，任何伪造都要同时改多处。",
                    "多来源互证：同一事实分别经 libc、直调 syscall、pidfd、clone3 沙箱子进程读取，差异本身即证据。",
                    "不可用 ≠ 安全：环境受限的检测项显式标记为「不可用」，绝不伪装成「正常」。",
                    "检测器自身可信：代码段快照、函数序言校验、JNI 表校验、openat2 双路径比对，反 Hook 命中直接判高风险。",
                    "只取证不攻击：不修改系统、不 ptrace、不加载内核模块、不使用任何远程校验。"
                ).forEach { line ->
                    Row(Modifier.padding(top = 6.dp)) {
                        Text("· ", color = Cyan, style = MaterialTheme.typography.bodySmall)
                        Text(
                            text = line,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                    }
                }
            }
        }

        // ---------------- 适用版本 ----------------
        item {
            GlassCard(modifier = Modifier.fillMaxWidth(), corner = 22.dp) {
                SectionHeader(title = "适用版本与场景")
                InfoRow("主要目标", "Android 15（API 35）/ CloreOS15 / AOSP15")
                InfoRow("兼容下限", "Android 11（API 30），更低版本缺少 pidfd / statx / clone3")
                InfoRow("适用环境", "KernelSU、Shamiko、Zygisk DenyList、LSPosed、HideMyApplist Next、susfs")
                InfoRow("不适用", "需要跨进程读取的场景（受 SELinux 限制时会标记不可用）")
                Text(
                    text = "在非 Root 的普通应用进程内运行；跨进程 procfs 读取被 SELinux 拒绝时，" +
                        "相关项以 available=false 呈现，不代表设备安全。",
                    style = MaterialTheme.typography.labelSmall,
                    color = TextMuted,
                    modifier = Modifier.padding(top = 8.dp)
                )
            }
        }

        // ---------------- 更新日志 ----------------
        item {
            GlassCard(modifier = Modifier.fillMaxWidth(), corner = 22.dp) {
                SectionHeader(title = "更新日志")
                ChangelogRow(
                    version = "1.0.1",
                    date = "2026-11-21",
                    highlights = listOf(
                        "正式版：1.0.1-rc 转正，检测项、判据、权重与打分模型均未变更",
                        "发版：versionCode 3；与 1.0.0 / 1.0.1-rc 同一签名，可直接覆盖升级",
                        "校验：v2 签名与证书指纹、双 ABI .so、51 项 ID 与版本串均已复核",
                        "文档：CHANGELOG、README、docs/01-06 同步本轮发版记录"
                    )
                )
                Spacer(Modifier.height(10.dp))
                ChangelogRow(
                    version = "1.0.1-rc",
                    date = "2026-11-21",
                    highlights = listOf(
                        "UI：新增底部三标签导航（测试 / 设置 / 关于），测试页为启动默认页",
                        "UI：新增「关于」页，包含应用信息、设计思路、适用版本、更新日志与开发人员",
                        "检测：新增 10 个检测项，总数 41 → 51（MNT-008/009、KRN-006/007、INJ-005、AHK-005/006、FOPS-001、ZYS-007/008）",
                        "检测：新增 openat2 与 openat 双路径比对、procfs 目录枚举过滤检测、函数地址段权限校验",
                        "文档：00-06 与 README 全量同步"
                    )
                )
                Spacer(Modifier.height(10.dp))
                ChangelogRow(
                    version = "1.0.0",
                    date = "2026-11-20",
                    highlights = listOf(
                        "首次发布：41 个检测项，Native 直调 syscall + clone3 沙箱 + 加权打分",
                        "Compose Material3 仪表盘：环形风险表、流式证据、毛玻璃卡片、全局背景与雪花",
                        "支持 JSON / Markdown / HTML 报告导出与分享"
                    )
                )
            }
        }

        // ---------------- 开发人员 ----------------
        item {
            GlassCard(modifier = Modifier.fillMaxWidth(), corner = 22.dp) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Filled.Person,
                        contentDescription = null,
                        tint = Cyan,
                        modifier = Modifier.size(18.dp)
                    )
                    Text(
                        text = "开发人员",
                        style = MaterialTheme.typography.titleSmall,
                        modifier = Modifier.padding(start = 6.dp)
                    )
                }
                Text(
                    text = "本应用由 DEEPSEEK-V4.1-Flash 编写",
                    style = MaterialTheme.typography.bodyMedium,
                    color = Color(0xFFBFD6FF),
                    modifier = Modifier.padding(top = 8.dp)
                )
                Text(
                    text = "设计、Native 检测核心、Compose 界面与全部文档均由 DEEPSEEK-V4.1-Flash 完成。",
                    style = MaterialTheme.typography.labelSmall,
                    color = TextMuted,
                    modifier = Modifier.padding(top = 6.dp)
                )
                Row(
                    modifier = Modifier.padding(top = 10.dp),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    TagChip(text = "Kotlin 2.0", color = ColdBlue)
                    TagChip(text = "Compose Material3", color = Cyan)
                    TagChip(text = "C11 / NDK 27", color = Color(0xFF9AA9B8))
                    TagChip(text = "API 35", color = Color(0xFF9AA9B8))
                }
            }
        }

        // ---------------- 合规声明 ----------------
        item {
            GlassCard(modifier = Modifier.fillMaxWidth(), corner = 22.dp, tint = 0.55f) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Filled.Code,
                        contentDescription = null,
                        tint = TextMuted,
                        modifier = Modifier.size(16.dp)
                    )
                    Text(
                        text = "合规声明",
                        style = MaterialTheme.typography.titleSmall,
                        modifier = Modifier.padding(start = 6.dp)
                    )
                }
                Text(
                    text = "本应用仅用于设备本地的痕迹检测与证据采集，不包含任何绕过、攻击、提权或修改 " +
                        "KernelSU / Magisk / LSPosed 环境的功能；不采集、不上传任何用户数据；" +
                        "不进行 SafetyNet / Play Integrity 等远程校验。",
                    style = MaterialTheme.typography.labelSmall,
                    color = TextMuted,
                    modifier = Modifier.padding(top = 8.dp)
                )
            }
        }

        item { Spacer(Modifier.height(30.dp)) }
    }
}

@Composable
private fun ChangelogRow(version: String, date: String, highlights: List<String>) {
    Column {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                imageVector = Icons.Filled.SystemUpdate,
                contentDescription = null,
                tint = Cyan,
                modifier = Modifier.size(15.dp)
            )
            Text(
                text = version,
                style = MaterialTheme.typography.titleSmall,
                modifier = Modifier.padding(start = 6.dp)
            )
            Text(
                text = "  $date",
                style = MaterialTheme.typography.labelSmall,
                color = TextMuted
            )
        }
        highlights.forEach { line ->
            Row(Modifier.padding(top = 5.dp)) {
                Text("· ", color = Cyan, style = MaterialTheme.typography.bodySmall)
                Text(
                    text = line,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurface
                )
            }
        }
    }
}
