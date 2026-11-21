package com.rasp.detect.ui.components

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue

/** 骨架屏呼吸动画（错峰相位，视觉上呈流式加载感）。 */
@Composable
fun rememberShimmerAlpha(index: Int = 0): Float {
    val transition = rememberInfiniteTransition(label = "shimmer-$index")
    val alpha by transition.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 1100, delayMillis = (index % 4) * 130, easing = LinearEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "shimmer-alpha-$index"
    )
    return alpha
}
