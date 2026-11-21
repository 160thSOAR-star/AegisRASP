package com.rasp.detect.ui.components

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.rasp.detect.Evidence
import com.rasp.detect.ReportExporter
import com.rasp.detect.ui.theme.Amber
import com.rasp.detect.ui.theme.SafeGreen
import com.rasp.detect.ui.theme.TextMuted
import com.rasp.detect.ui.theme.WarnRed
import com.rasp.detect.ui.theme.gradeColor
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * 可展开折叠的检测项卡片：
 * 收起显示 名称 / 状态图标 / 置信度 / 证据等级；展开显示原始证据 JSON、错误信息、采集时间。
 */
@Composable
fun EvidenceCard(
    evidence: Evidence,
    modifier: Modifier = Modifier
) {
    var expanded by rememberSaveable(evidence.id) { mutableStateOf(false) }
    val arrowRotation by animateFloatAsState(
        targetValue = if (expanded) 180f else 0f,
        animationSpec = tween(260),
        label = "arrow"
    )
    val accent = gradeColor(evidence.grade.key)

    GlassCard(
        modifier = modifier.fillMaxWidth(),
        corner = 20.dp,
        tint = 0.62f,
        contentPadding = 14.dp
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clickable { expanded = !expanded },
            verticalAlignment = Alignment.CenterVertically
        ) {
            val (icon, iconColor, label) = when {
                !evidence.available -> Triple(Icons.Filled.Block, TextMuted, "不可用")
                evidence.hit -> Triple(Icons.Filled.ErrorOutline, WarnRed, "命中")
                else -> Triple(Icons.Filled.CheckCircle, SafeGreen, "正常")
            }
            Icon(
                imageVector = icon,
                contentDescription = label,
                tint = iconColor,
                modifier = Modifier.size(20.dp)
            )
            Spacer(Modifier.width(10.dp))
            Column(Modifier.weight(1f)) {
                Text(
                    text = evidence.name,
                    style = MaterialTheme.typography.titleSmall,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = evidence.id,
                        style = MaterialTheme.typography.labelSmall,
                        color = TextMuted
                    )
                    Text(
                        text = " · ${ReportExporter.categoryLabel(evidence.category)}",
                        style = MaterialTheme.typography.labelSmall,
                        color = TextMuted,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }
            Column(horizontalAlignment = Alignment.End) {
                TagChip(text = evidence.grade.label, color = accent)
                Text(
                    text = "${(evidence.confidence * 100).toInt()}%",
                    style = MaterialTheme.typography.labelSmall,
                    color = if (evidence.hit) accent else TextMuted,
                    modifier = Modifier.padding(top = 4.dp)
                )
            }
            Icon(
                imageVector = Icons.Filled.ExpandMore,
                contentDescription = if (expanded) "收起" else "展开",
                tint = TextMuted,
                modifier = Modifier
                    .padding(start = 4.dp)
                    .size(20.dp)
                    .rotate(arrowRotation)
            )
        }

        AnimatedVisibility(
            visible = expanded,
            enter = expandVertically(tween(260)) + fadeIn(tween(200)),
            exit = shrinkVertically(tween(220)) + fadeOut(tween(120))
        ) {
            Column(Modifier.fillMaxWidth()) {
                HorizontalDivider(
                    modifier = Modifier.padding(vertical = 12.dp),
                    color = Color(0xFF22303F)
                )
                Text(
                    text = "原始证据",
                    style = MaterialTheme.typography.labelSmall,
                    color = TextMuted
                )
                Box(
                    Modifier
                        .padding(top = 6.dp)
                        .fillMaxWidth()
                        .background(Color(0xCC050A12), RoundedCornerShape(12.dp))
                        .padding(12.dp)
                ) {
                    Text(
                        text = evidence.rawPretty,
                        style = MaterialTheme.typography.bodySmall.copy(
                            fontFamily = FontFamily.Monospace,
                            fontSize = 11.sp
                        ),
                        color = Color(0xFF9FC3DE)
                    )
                }
                if (evidence.error.isNotBlank()) {
                    Text(
                        text = "限制 / 错误：${evidence.error}",
                        style = MaterialTheme.typography.bodySmall,
                        color = Amber,
                        modifier = Modifier.padding(top = 8.dp)
                    )
                }
                Text(
                    text = "采集时间：${
                        SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())
                            .format(Date(evidence.timestamp))
                    }",
                    style = MaterialTheme.typography.labelSmall,
                    color = TextMuted,
                    modifier = Modifier.padding(top = 8.dp)
                )
            }
        }
    }
}

/** 检测进行中的骨架屏（流式占位）。 */
@Composable
fun SkeletonCheckRow(modifier: Modifier = Modifier, index: Int = 0) {
    val shimmer = rememberShimmerAlpha(index)
    GlassCard(
        modifier = modifier.fillMaxWidth(),
        corner = 20.dp,
        tint = 0.38f,
        contentPadding = 14.dp
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier
                    .size(20.dp)
                    .background(Color(0xFF1B2836).copy(alpha = 0.4f + 0.5f * shimmer), RoundedCornerShape(10.dp))
            )
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Box(
                    Modifier
                        .fillMaxWidth(0.72f)
                        .height(12.dp)
                        .background(Color(0xFF1B2836).copy(alpha = 0.35f + 0.5f * shimmer), RoundedCornerShape(6.dp))
                )
                Box(
                    Modifier
                        .fillMaxWidth(0.42f)
                        .height(9.dp)
                        .background(Color(0xFF1B2836).copy(alpha = 0.25f + 0.4f * shimmer), RoundedCornerShape(5.dp))
                )
            }
            Box(
                Modifier
                    .width(52.dp)
                    .height(18.dp)
                    .background(Color(0xFF1B2836).copy(alpha = 0.3f + 0.4f * shimmer), RoundedCornerShape(9.dp))
            )
        }
    }
}
