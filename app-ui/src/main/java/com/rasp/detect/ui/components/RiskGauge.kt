package com.rasp.detect.ui.components

import androidx.compose.animation.core.CubicBezierEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.rasp.detect.RiskLevel
import com.rasp.detect.ui.theme.Amber
import com.rasp.detect.ui.theme.Cyan
import com.rasp.detect.ui.theme.SafeGreen
import com.rasp.detect.ui.theme.TextMuted
import com.rasp.detect.ui.theme.WarnRed
import kotlin.math.cos
import kotlin.math.sin

private fun levelColor(level: RiskLevel): Color = when (level) {
    RiskLevel.SAFE -> SafeGreen
    RiskLevel.SUSPICIOUS -> Amber
    RiskLevel.HIGH -> WarnRed
}

/**
 * 自定义 Compose 环形仪表盘：
 *  - 0-100 风险得分，270° 表盘，绿/黄/红分段；
 *  - 分数变化带平滑过渡动画（CubicBezier）；
 *  - 刻度线 + 进度弧 + 呼吸光晕。
 */
@Composable
fun RiskGauge(
    score: Int,
    level: RiskLevel,
    confidence: Double,
    size: Dp = 236.dp,
    modifier: Modifier = Modifier
) {
    val animated by animateFloatAsState(
        targetValue = score.coerceIn(0, 100).toFloat(),
        animationSpec = tween(durationMillis = 1300, easing = CubicBezierEasing(0.2f, 0.9f, 0.2f, 1f)),
        label = "risk-score"
    )
    val color = levelColor(level)
    val pulse by rememberInfiniteTransition(label = "pulse").animateFloat(
        initialValue = 0.35f,
        targetValue = 0.75f,
        animationSpec = infiniteRepeatable(tween(2200), RepeatMode.Reverse),
        label = "pulse-alpha"
    )

    Box(contentAlignment = Alignment.Center, modifier = modifier.size(size)) {
        val trackColor = Color(0xFF152134)
        Canvas(modifier = Modifier.matchParentSize()) {
            val stroke = 16.dp.toPx()
            val inset = stroke / 2 + 10.dp.toPx()
            val arcSize = Size(this.size.width - inset * 2, this.size.height - inset * 2)
            val topLeft = Offset(inset, inset)
            val start = 135f
            val sweepMax = 270f

            // 轨道
            drawArc(
                color = trackColor,
                startAngle = start,
                sweepAngle = sweepMax,
                useCenter = false,
                topLeft = topLeft,
                size = arcSize,
                style = Stroke(width = stroke, cap = StrokeCap.Round)
            )

            // 刻度
            val centerPt = Offset(this.size.width / 2, this.size.height / 2)
            val radius = this.size.width / 2 - inset
            for (i in 0..40) {
                val angle = Math.toRadians((start + sweepMax * i / 40f).toDouble())
                val inner = radius - stroke / 2 - 7.dp.toPx()
                val outer = radius - stroke / 2 + 2.dp.toPx()
                val active = i / 40f <= animated / 100f
                drawLine(
                    color = if (active) color.copy(alpha = 0.75f) else trackColor.copy(alpha = 0.9f),
                    start = Offset(
                        centerPt.x + (inner * cos(angle)).toFloat(),
                        centerPt.y + (inner * sin(angle)).toFloat()
                    ),
                    end = Offset(
                        centerPt.x + (outer * cos(angle)).toFloat(),
                        centerPt.y + (outer * sin(angle)).toFloat()
                    ),
                    strokeWidth = 2.dp.toPx(),
                    cap = StrokeCap.Round
                )
            }

            // 进度弧（渐变扫过）
            val sweep = sweepMax * (animated / 100f)
            if (sweep > 0.5f) {
                drawArc(
                    brush = Brush.sweepGradient(
                        listOf(
                            Cyan.copy(alpha = 0.9f),
                            SafeGreen,
                            Amber,
                            WarnRed
                        )
                    ),
                    startAngle = start,
                    sweepAngle = sweep,
                    useCenter = false,
                    topLeft = topLeft,
                    size = arcSize,
                    style = Stroke(width = stroke, cap = StrokeCap.Round)
                )
                // 端点光晕
                val endAngle = Math.toRadians((start + sweep).toDouble())
                val r = radius
                drawCircle(
                    color = color.copy(alpha = pulse),
                    radius = stroke * 0.55f,
                    center = Offset(
                        centerPt.x + (r * cos(endAngle)).toFloat(),
                        centerPt.y + (r * sin(endAngle)).toFloat()
                    )
                )
            }
        }

        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
            modifier = Modifier.padding(top = 6.dp)
        ) {
            Text(
                text = animated.toInt().toString(),
                style = MaterialTheme.typography.displaySmall,
                color = color,
                fontWeight = FontWeight.Bold
            )
            Text(
                text = "风险得分 / 100",
                style = MaterialTheme.typography.labelSmall,
                color = TextMuted
            )
            TagChip(
                text = level.label,
                color = color,
                modifier = Modifier.padding(top = 10.dp)
            )
            Text(
                text = "置信度 ${(confidence * 100).toInt()}%",
                style = MaterialTheme.typography.labelSmall,
                color = TextMuted,
                modifier = Modifier.padding(top = 8.dp)
            )
        }
    }
}
