package com.rasp.detect.ui.components

import android.app.ActivityManager
import android.content.Context
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.withFrameNanos
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import kotlin.math.sin
import kotlin.random.Random

/**
 * 全屏雪花飘落层（纯 Canvas 自绘，不引入任何第三方库）。
 *
 * 层级：背景层 → 雪花层 → 内容卡片层。雪花层不消费触摸事件（Canvas 默认不处理点击），
 * 因此不会遮挡按钮点击与列表滚动。
 * 性能：低端设备自动降采样（数量减半、30fps 更新）；页面不可见时自动暂停。
 */
@Composable
fun SnowfallLayer(
    enabled: Boolean,
    density: Float,
    sizeScale: Float,
    speedScale: Float,
    opacity: Float,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val lowRam = remember(context) {
        val am = context.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager
        am?.isLowRamDevice == true
    }

    val lifecycle = LocalLifecycleOwner.current.lifecycle
    var resumed by remember { mutableStateOf(lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) }
    DisposableEffect(lifecycle) {
        val observer = LifecycleEventObserver { _, event ->
            when (event) {
                Lifecycle.Event.ON_RESUME -> resumed = true
                Lifecycle.Event.ON_PAUSE -> resumed = false
                else -> Unit
            }
        }
        lifecycle.addObserver(observer)
        onDispose { lifecycle.removeObserver(observer) }
    }

    val count = remember(density, lowRam) {
        val base = if (lowRam) 55 else 95
        (base + (density.coerceIn(0f, 1f) * (if (lowRam) 70 else 150)).toInt()).coerceAtLeast(1)
    }

    val snow = remember { SnowState() }
    var tick by remember { mutableIntStateOf(0) }

    LaunchedEffect(enabled, resumed, count, sizeScale, speedScale) {
        if (!enabled || !resumed) return@LaunchedEffect
        snow.configure(count, sizeScale, speedScale)
        var last = 0L
        var carry = 0f
        val frameGate = if (lowRam) 1f / 30f else 0f
        while (true) {
            withFrameNanos { now ->
                if (last != 0L) {
                    val dt = ((now - last) / 1_000_000_000.0).toFloat().coerceAtMost(0.06f)
                    carry += dt
                    if (carry >= frameGate) {
                        snow.step(carry)
                        carry = 0f
                        tick++
                    }
                }
                last = now
            }
        }
    }

    Canvas(modifier = modifier.fillMaxSize()) {
        // 在绘制阶段读取 tick，只触发重绘，不触发重组
        @Suppress("UNUSED_EXPRESSION")
        tick
        snow.draw(this, opacity)
    }
}

private class Flake {
    var x = 0f
    var y = 0f
    var radius = 1f
    var velocity = 0f
    var sway = 0f
    var phase = 0f
    var alpha = 1f
}

private class SnowState {
    val flakes = ArrayList<Flake>(256)
    private val random = Random(20260101)
    private var time = 0f

    fun configure(count: Int, sizeScale: Float, speedScale: Float) {
        flakes.clear()
        val s = 0.45f + sizeScale.coerceIn(0f, 1f) * 1.55f
        val v = 0.4f + speedScale.coerceIn(0f, 1f) * 1.8f
        repeat(count) {
            flakes.add(
                Flake().apply {
                    x = random.nextFloat()
                    y = random.nextFloat()
                    radius = (0.7f + random.nextFloat() * 2.1f) * s
                    velocity = (0.018f + random.nextFloat() * 0.052f) * v
                    sway = 0.004f + random.nextFloat() * 0.013f
                    phase = random.nextFloat() * 6.2832f
                    alpha = 0.30f + random.nextFloat() * 0.65f
                }
            )
        }
        time = 0f
    }

    fun step(dt: Float) {
        time += dt
        for (f in flakes) {
            f.y += f.velocity * dt
            f.x += sin(time * 1.1f + f.phase) * f.sway * dt * 8f
            if (f.y > 1.06f) {
                f.y = -0.06f
                f.x = random.nextFloat()
            }
            if (f.x < -0.06f) f.x = 1.06f
            if (f.x > 1.06f) f.x = -0.06f
        }
    }

    fun draw(scope: DrawScope, opacity: Float) {
        val o = opacity.coerceIn(0f, 1f)
        if (o <= 0f) return
        val w = scope.size.width
        val h = scope.size.height
        val unit = scope.size.minDimension * 0.0032f
        for (f in flakes) {
            val center = Offset(f.x * w, f.y * h)
            val r = f.radius * unit
            // 外圈柔光 + 内核实心，模拟雪花边缘渐隐
            scope.drawCircle(
                color = Color(0xFFCFE9FF).copy(alpha = f.alpha * o * 0.16f),
                radius = r * 2.3f,
                center = center
            )
            scope.drawCircle(
                color = Color.White.copy(alpha = f.alpha * o * 0.9f),
                radius = r,
                center = center
            )
        }
    }
}
