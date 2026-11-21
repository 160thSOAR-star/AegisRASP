package com.rasp.detect.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.rasp.detect.ui.theme.Panel
import com.rasp.detect.ui.theme.TextMuted

/**
 * 毛玻璃质感卡片：
 *  - 大圆角 + 弱边框 + 细腻外阴影；
 *  - 半透明深色底 + 顶部高光渐变，模拟雾面磨砂；
 *  - 真正的背景高斯模糊由背景层统一处理（见 AegisBackground），避免每张卡重复采样。
 */
@Composable
fun GlassCard(
    modifier: Modifier = Modifier,
    corner: Dp = 24.dp,
    tint: Float = 0.72f,
    contentPadding: Dp = 18.dp,
    content: @Composable ColumnScope.() -> Unit
) {
    val shape = RoundedCornerShape(corner)
    Column(
        modifier = modifier
            .shadow(
                elevation = 18.dp,
                shape = shape,
                ambientColor = Color.Black.copy(alpha = 0.55f),
                spotColor = Color(0xFF4C8DFF).copy(alpha = 0.12f)
            )
            .clip(shape)
            .background(Panel.copy(alpha = tint))
            .background(
                Brush.verticalGradient(
                    listOf(
                        Color.White.copy(alpha = 0.09f),
                        Color.White.copy(alpha = 0.02f),
                        Color.Transparent
                    )
                )
            )
            .border(
                width = 1.dp,
                brush = Brush.linearGradient(
                    listOf(
                        Color.White.copy(alpha = 0.20f),
                        Color(0xFF4C8DFF).copy(alpha = 0.10f),
                        Color.White.copy(alpha = 0.04f)
                    )
                ),
                shape = shape
            )
            .padding(contentPadding),
        content = content
    )
}

/** 小标签（证据等级 / 状态）。 */
@Composable
fun TagChip(
    text: String,
    color: Color,
    modifier: Modifier = Modifier
) {
    Text(
        text = text,
        style = MaterialTheme.typography.labelSmall,
        color = color,
        modifier = modifier
            .clip(RoundedCornerShape(999.dp))
            .background(color.copy(alpha = 0.14f))
            .border(1.dp, color.copy(alpha = 0.35f), RoundedCornerShape(999.dp))
            .padding(horizontal = 9.dp, vertical = 3.dp)
    )
}

/** 分组标题。 */
@Composable
fun SectionHeader(title: String, trailing: String? = null, modifier: Modifier = Modifier) {
    Row(
        modifier = modifier.padding(horizontal = 4.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(
            text = title,
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.onSurface
        )
        if (trailing != null) {
            Text(
                text = trailing,
                style = MaterialTheme.typography.labelSmall,
                color = TextMuted
            )
        }
    }
}

/** 键值信息行。 */
@Composable
fun InfoRow(label: String, value: String, modifier: Modifier = Modifier) {
    Row(
        modifier = modifier.padding(vertical = 3.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodySmall,
            color = TextMuted,
            modifier = Modifier.padding(end = 12.dp)
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurface
        )
    }
}
