package com.rasp.detect.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.BottomSheetDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.rasp.detect.Evidence
import com.rasp.detect.RaspReport
import com.rasp.detect.ReportExporter
import com.rasp.detect.ui.export.ExportManager
import com.rasp.detect.ui.theme.PanelDeep
import com.rasp.detect.ui.theme.TextMuted
import com.rasp.detect.ui.theme.gradeColor
import com.rasp.detect.ui.theme.riskColor
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * 报告预览弹窗：底部弹出 + 圆角容器 + 背景模糊遮罩（由 ModalBottomSheet 提供），
 * 支持滚动查看完整报告、逐条查看证据，并提供四种导出动作。
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ReportSheet(
    report: RaspReport,
    onDismiss: () -> Unit,
    onExport: (ExportManager.Format) -> Unit,
    onShare: () -> Unit,
    onCopyEvidence: (Evidence) -> Unit
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        containerColor = PanelDeep,
        scrimColor = Color.Black.copy(alpha = 0.62f),
        dragHandle = { BottomSheetDefaults.DragHandle(color = Color(0xFF2A3A4D)) }
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .fillMaxHeight(0.92f)
                .padding(horizontal = 18.dp)
        ) {
            Text(
                text = "检测报告",
                style = MaterialTheme.typography.headlineSmall
            )
            Text(
                text = "${report.level.label} · 得分 ${report.score} / 100 · 置信度 ${
                    (report.confidence * 100).toInt()
                }% · 耗时 ${report.durationMs} ms",
                style = MaterialTheme.typography.bodySmall,
                color = riskColor(report.level.key),
                modifier = Modifier.padding(top = 6.dp)
            )
            Text(
                text = "${report.device.model} · Android ${report.device.release} (API ${report.device.sdk}) · ${report.device.abi} · " +
                    "强 ${report.counts.strong} / 间接 ${report.counts.indirect} / 弱 ${report.counts.weak}",
                style = MaterialTheme.typography.labelSmall,
                color = TextMuted,
                modifier = Modifier.padding(top = 4.dp)
            )
            if (report.antiHookHit) {
                Text(
                    text = "⚠ 反 Hook 自校验命中：检测逻辑疑似被篡改，判定直接升级为高风险",
                    style = MaterialTheme.typography.bodySmall,
                    color = Color(0xFFFF8080),
                    modifier = Modifier.padding(top = 8.dp)
                )
            }

            LazyColumn(
                modifier = Modifier
                    .weight(1f)
                    .padding(top = 12.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                val hits = report.items.filter { it.hit }
                if (hits.isNotEmpty()) {
                    item {
                        SectionHeader("命中证据", "${hits.size} 项")
                    }
                }
                items(report.items, key = { it.id }) { ev ->
                    ReportRow(ev = ev, onClick = { onCopyEvidence(ev) })
                }
                item { Spacer(Modifier.height(12.dp)) }
            }

            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 12.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                ExportButton("JSON", Modifier.weight(1f)) { onExport(ExportManager.Format.JSON) }
                ExportButton("MD", Modifier.weight(1f)) { onExport(ExportManager.Format.MARKDOWN) }
                ExportButton("HTML", Modifier.weight(1f)) { onExport(ExportManager.Format.HTML) }
                ExportButton("分享", Modifier.weight(1f)) { onShare() }
            }
        }
    }
}

@Composable
private fun ReportRow(ev: Evidence, onClick: () -> Unit) {
    val accent = gradeColor(ev.grade.key)
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(Color(0xFF0B121C), RoundedCornerShape(16.dp))
            .clickable { onClick() }
            .padding(12.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                text = ev.id,
                style = MaterialTheme.typography.labelSmall,
                color = TextMuted,
                modifier = Modifier.padding(end = 8.dp)
            )
            Text(
                text = ev.name,
                style = MaterialTheme.typography.titleSmall,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f)
            )
            TagChip(
                text = if (ev.hit) "命中" else if (!ev.available) "不可用" else "正常",
                color = if (ev.hit) accent else TextMuted
            )
        }
        Text(
            text = "${ReportExporter.categoryLabel(ev.category)} · ${ev.grade.label} · 置信度 ${
                (ev.confidence * 100).toInt()
            }%",
            style = MaterialTheme.typography.labelSmall,
            color = TextMuted,
            modifier = Modifier.padding(top = 4.dp)
        )
        if (ev.hit) {
            Text(
                text = ev.rawPretty.take(320),
                style = MaterialTheme.typography.bodySmall.copy(
                    fontFamily = FontFamily.Monospace,
                    fontSize = 10.sp
                ),
                color = Color(0xFF8FB3CC),
                modifier = Modifier.padding(top = 6.dp),
                maxLines = 4,
                overflow = TextOverflow.Ellipsis
            )
        }
        Text(
            text = "点击复制原始证据 · " +
                SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date(ev.timestamp)),
            style = MaterialTheme.typography.labelSmall,
            color = Color(0xFF4C8DFF).copy(alpha = 0.7f),
            modifier = Modifier.padding(top = 6.dp)
        )
    }
}

@Composable
private fun ExportButton(label: String, modifier: Modifier = Modifier, onClick: () -> Unit) {
    Text(
        text = label,
        style = MaterialTheme.typography.labelSmall,
        color = Color(0xFFBFD6FF),
        modifier = modifier
            .background(
                Brush.verticalGradient(listOf(Color(0xFF1B2F4A), Color(0xFF122033))),
                RoundedCornerShape(12.dp)
            )
            .clickable { onClick() }
            .padding(vertical = 11.dp),
        textAlign = androidx.compose.ui.text.style.TextAlign.Center
    )
}
