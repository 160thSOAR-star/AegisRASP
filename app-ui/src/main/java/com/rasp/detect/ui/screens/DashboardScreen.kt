package com.rasp.detect.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.rasp.detect.CheckCatalog
import com.rasp.detect.Evidence
import com.rasp.detect.ui.AppSettings
import com.rasp.detect.ui.DetectPhase
import com.rasp.detect.ui.RaspUiState
import com.rasp.detect.ui.components.EvidenceCard
import com.rasp.detect.ui.components.GlassCard
import com.rasp.detect.ui.components.InfoRow
import com.rasp.detect.ui.components.RiskGauge
import com.rasp.detect.ui.components.SectionHeader
import com.rasp.detect.ui.components.SkeletonCheckRow
import com.rasp.detect.ui.components.TagChip
import com.rasp.detect.ui.export.ExportManager
import com.rasp.detect.ui.theme.ColdBlue
import com.rasp.detect.ui.theme.Cyan
import com.rasp.detect.ui.theme.SafeGreen
import com.rasp.detect.ui.theme.TextMuted
import com.rasp.detect.ui.theme.riskColor

/** 主仪表盘。 */
@Composable
fun DashboardScreen(
    state: RaspUiState,
    settings: AppSettings,
    onStart: () -> Unit,
    onCancel: () -> Unit,
    onPreviewReport: () -> Unit,
    onExport: (ExportManager.Format) -> Unit,
    onShare: () -> Unit,
    onDismissDiagnostic: () -> Unit = {}
) {
    var reveal by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) { reveal = true }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 10.dp, bottom = 2.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    modifier = Modifier
                        .size(42.dp)
                        .clip(RoundedCornerShape(14.dp))
                        .background(
                            Brush.linearGradient(
                                listOf(Cyan.copy(alpha = 0.22f), ColdBlue.copy(alpha = 0.16f))
                            )
                        ),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = Icons.Filled.Security,
                        contentDescription = null,
                        tint = Cyan,
                        modifier = Modifier.size(22.dp)
                    )
                }
                Spacer(Modifier.width(12.dp))
                Column(Modifier.weight(1f)) {
                    Text(
                        text = "AEGIS RASP",
                        style = MaterialTheme.typography.headlineSmall,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = "KernelSU 运行时检测 · API 36+",
                        style = MaterialTheme.typography.labelSmall,
                        color = TextMuted
                    )
                }
            }
        }
        if (state.diagnostic != null) {
            item {
                GlassCard(modifier = Modifier.fillMaxWidth(), corner = 20.dp, tint = 0.66f) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = "上次检测异常退出",
                            style = MaterialTheme.typography.titleSmall,
                            color = com.rasp.detect.ui.theme.Amber,
                            modifier = Modifier.weight(1f)
                        )
                        Text(
                            text = "知道了",
                            style = MaterialTheme.typography.labelSmall,
                            color = Cyan,
                            modifier = Modifier.clickable { onDismissDiagnostic() }
                        )
                    }
                    Text(
                        text = state.diagnostic,
                        style = MaterialTheme.typography.bodySmall,
                        color = TextMuted,
                        modifier = Modifier.padding(top = 8.dp)
                    )
                }
            }
        }

        item {
            AnimatedVisibility(
                visible = reveal,
                enter = fadeIn(tween(420)) + androidx.compose.animation.scaleIn(tween(420), initialScale = 0.94f),
                exit = fadeOut()
            ) {
                GlassCard(modifier = Modifier.fillMaxWidth(), corner = 26.dp) {
                    Column(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        RiskGauge(
                            score = state.score,
                            level = state.level,
                            confidence = state.confidence
                        )
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(top = 10.dp),
                            horizontalArrangement = Arrangement.SpaceEvenly
                        ) {
                            StatBlock(
                                value = "${state.report?.counts?.strong ?: 0}",
                                label = "强证据",
                                color = com.rasp.detect.ui.theme.WarnRed
                            )
                            StatBlock(
                                value = "${state.report?.counts?.indirect ?: 0}",
                                label = "间接证据",
                                color = com.rasp.detect.ui.theme.Amber
                            )
                            StatBlock(
                                value = "${state.report?.counts?.weak ?: 0}",
                                label = "弱线索",
                                color = TextMuted
                            )
                            StatBlock(
                                value = if (state.elapsedMs > 0) "${state.elapsedMs}ms" else "—",
                                label = "耗时",
                                color = ColdBlue
                            )
                        }
                        if (state.phase == DetectPhase.DONE && state.report != null) {
                            Text(
                                text = state.level.summary,
                                style = MaterialTheme.typography.bodySmall,
                                color = riskColor(state.level.key),
                                textAlign = TextAlign.Center,
                                modifier = Modifier.padding(top = 10.dp)
                            )
                        }
                        PrimaryAction(
                            phase = state.phase,
                            onStart = onStart,
                            onCancel = onCancel,
                            modifier = Modifier.padding(top = 14.dp)
                        )
                    }
                }
            }
        }

        if (state.phase == DetectPhase.RUNNING) {
            item {
                GlassCard(modifier = Modifier.fillMaxWidth(), corner = 22.dp, tint = 0.6f) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = "正在执行本地检测",
                            style = MaterialTheme.typography.titleSmall,
                            modifier = Modifier.weight(1f)
                        )
                        TagChip(text = "${state.progressDone}/${state.progressTotal}", color = Cyan)
                    }
                    LinearProgressIndicator(
                        progress = { state.progress },
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 12.dp)
                            .height(6.dp)
                            .clip(RoundedCornerShape(3.dp)),
                        color = Cyan,
                        trackColor = Color(0xFF16222F)
                    )
                    Text(
                        text = "Native 层异步批处理中：证据逐条流式回传，主线程不阻塞",
                        style = MaterialTheme.typography.labelSmall,
                        color = TextMuted,
                        modifier = Modifier.padding(top = 10.dp)
                    )
                }
            }
            items(2) { index ->
                SkeletonCheckRow(index = index)
            }
        }

        if (state.phase == DetectPhase.FAILED) {
            item {
                GlassCard(modifier = Modifier.fillMaxWidth(), corner = 22.dp) {
                    Text(
                        text = "检测失败",
                        style = MaterialTheme.typography.titleSmall,
                        color = com.rasp.detect.ui.theme.WarnRed
                    )
                    Text(
                        text = state.error ?: "未知错误",
                        style = MaterialTheme.typography.bodySmall,
                        color = TextMuted,
                        modifier = Modifier.padding(top = 6.dp)
                    )
                }
            }
        }

        if (state.items.isNotEmpty()) {
            item {
                SectionHeader(
                    title = "检测证据",
                    trailing = "命中 ${state.hitItems.size} / ${state.items.size}"
                )
            }
            val ordered: List<Evidence> = state.items.sortedWith(
                compareByDescending<Evidence> { it.hit }
                    .thenByDescending { it.grade.ordinal }
                    .thenByDescending { it.confidence }
            )
            items(ordered, key = { it.id }) { ev ->
                EvidenceCard(evidence = ev)
            }
        } else if (state.phase == DetectPhase.IDLE) {
            item {
                GlassCard(modifier = Modifier.fillMaxWidth(), corner = 22.dp, tint = 0.55f) {
                    Text(
                        text = "将执行 ${CheckCatalog.total} 项本地检测",
                        style = MaterialTheme.typography.titleSmall
                    )
                    Text(
                        text = "覆盖挂载命名空间、KernelSU 进程、内核态间接痕迹、BPF、Zygisk/Shamiko/LSPosed、" +
                            "注入与 ptrace、SELinux/AVB、反 Hook 自校验八大类。全部为本地痕迹采集，" +
                            "不发起任何远程校验请求。",
                        style = MaterialTheme.typography.bodySmall,
                        color = TextMuted,
                        modifier = Modifier.padding(top = 8.dp)
                    )
                    Column(Modifier.padding(top = 10.dp)) {
                        InfoRow("耗时预期", "完整模式 2-6s · 快速模式 < 2s")
                        InfoRow("权限要求", "无（普通应用，非 Root）")
                        InfoRow("调度策略", if (settings.fastMode) "快速模式（跳过高开销项）" else "分级调度")
                    }
                }
            }
        }

        if (state.report != null) {
            item {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 4.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    ActionChip(
                        text = "预览报告",
                        modifier = Modifier.weight(1f),
                        onClick = onPreviewReport
                    )
                    ActionChip(
                        text = "导出 JSON",
                        modifier = Modifier.weight(1f),
                        onClick = { onExport(ExportManager.Format.JSON) }
                    )
                    ActionChip(
                        text = "分享",
                        modifier = Modifier.weight(1f),
                        icon = { Icon(Icons.Filled.Share, null, tint = Color(0xFFBFD6FF), modifier = Modifier.size(14.dp)) },
                        onClick = onShare
                    )
                }
            }
        }

        item {
            Text(
                text = "纯本地检测 · 无网络请求 · 仅采集痕迹证据，不修改任何系统状态",
                style = MaterialTheme.typography.labelSmall,
                color = TextMuted.copy(alpha = 0.75f),
                textAlign = TextAlign.Center,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 14.dp, bottom = 26.dp)
            )
        }
    }
}

@Composable
private fun StatBlock(value: String, label: String, color: Color) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(
            text = value,
            style = MaterialTheme.typography.titleMedium,
            color = color,
            fontWeight = FontWeight.SemiBold
        )
        Text(text = label, style = MaterialTheme.typography.labelSmall, color = TextMuted)
    }
}

@Composable
private fun PrimaryAction(
    phase: DetectPhase,
    onStart: () -> Unit,
    onCancel: () -> Unit,
    modifier: Modifier = Modifier
) {
    val running = phase == DetectPhase.RUNNING
    val label = when (phase) {
        DetectPhase.IDLE -> "开始检测"
        DetectPhase.RUNNING -> "停止检测"
        DetectPhase.DONE -> "重新检测"
        DetectPhase.FAILED -> "重试"
    }
    Row(
        modifier = modifier
            .fillMaxWidth()
            .height(50.dp)
            .clip(RoundedCornerShape(16.dp))
            .background(
                Brush.horizontalGradient(
                    if (running) listOf(Color(0xFF3A2230), Color(0xFF2A1A24))
                    else listOf(Cyan.copy(alpha = 0.24f), ColdBlue.copy(alpha = 0.30f))
                )
            )
            .clickable { if (running) onCancel() else onStart() },
        horizontalArrangement = Arrangement.Center,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            imageVector = if (running) Icons.Filled.Stop else Icons.Filled.Refresh,
            contentDescription = null,
            tint = if (running) com.rasp.detect.ui.theme.WarnRed else Cyan,
            modifier = Modifier.size(18.dp)
        )
        Spacer(Modifier.width(8.dp))
        Text(
            text = label,
            style = MaterialTheme.typography.titleSmall,
            color = if (running) com.rasp.detect.ui.theme.WarnRed else SafeGreen
        )
    }
}

@Composable
private fun ActionChip(
    text: String,
    modifier: Modifier = Modifier,
    icon: @Composable (() -> Unit)? = null,
    onClick: () -> Unit
) {
    Row(
        modifier = modifier
            .height(46.dp)
            .clip(RoundedCornerShape(14.dp))
            .background(Color(0xFF111C2A))
            .clickable { onClick() },
        horizontalArrangement = Arrangement.Center,
        verticalAlignment = Alignment.CenterVertically
    ) {
        if (icon != null) {
            icon()
            Spacer(Modifier.width(6.dp))
        }
        Text(text = text, style = MaterialTheme.typography.labelSmall, color = Color(0xFFBFD6FF))
    }
}
