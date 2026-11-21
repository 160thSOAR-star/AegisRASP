package com.rasp.detect.ui.components

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import android.os.Build
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.blur
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.PointMode
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.rasp.detect.ui.AppSettings
import com.rasp.detect.ui.theme.DeepNight
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import kotlin.random.Random

/**
 * 全局背景系统：
 *  图片层（可选，支持高斯模糊）→ 冷调柔光 → 雾面磨砂 → 暗角 → 颗粒噪点。
 * 所有图层都由设置的实时参数驱动，调参立即生效（无需重启页面）。
 */
@Composable
fun AegisBackground(
    settings: AppSettings,
    modifier: Modifier = Modifier,
    content: @Composable BoxScope.() -> Unit
) {
    val bitmap by rememberBackgroundBitmap(settings.backgroundUri)

    Box(modifier = modifier.fillMaxSize().background(DeepNight)) {
        // 1) 内置渐变底色（无自定义图片时使用）
        Box(
            Modifier
                .fillMaxSize()
                .background(
                    Brush.radialGradient(
                        colors = listOf(Color(0xFF10243C), Color(0xFF08101C), DeepNight),
                        radius = 1600f
                    )
                )
        )

        // 2) 用户导入图片（可模糊）
        val bmp = bitmap
        if (bmp != null) {
            val blurModifier = if (settings.blurRadius > 0.5f) {
                Modifier.blur(settings.blurRadius.dp)
            } else {
                Modifier
            }
            Image(
                bitmap = bmp,
                contentDescription = null,
                contentScale = ContentScale.Crop,
                modifier = Modifier
                    .fillMaxSize()
                    .then(blurModifier)
                    .graphicsLayer { alpha = settings.backgroundOpacity.coerceIn(0f, 1f) }
            )
        }

        // 3) 冷调柔光
        if (settings.coldLight) {
            Box(
                Modifier
                    .fillMaxSize()
                    .background(
                        Brush.verticalGradient(
                            listOf(
                                Color(0xFF1E6E7A).copy(alpha = 0.20f),
                                Color.Transparent,
                                Color(0xFF2A4E8C).copy(alpha = 0.18f)
                            )
                        )
                    )
            )
        }

        // 4) 雾面磨砂层
        if (settings.frost > 0.01f) {
            Box(
                Modifier
                    .fillMaxSize()
                    .background(Color(0xFF070C14).copy(alpha = settings.frost.coerceIn(0f, 1f) * 0.55f))
            )
        }

        // 5) 暗角
        if (settings.vignette > 0.01f) {
            Box(
                Modifier
                    .fillMaxSize()
                    .drawBehind {
                        drawRect(
                            brush = Brush.radialGradient(
                                colors = listOf(
                                    Color.Transparent,
                                    Color.Black.copy(alpha = 0.92f * settings.vignette.coerceIn(0f, 1f))
                                ),
                                center = center,
                                radius = size.maxDimension * 0.72f
                            )
                        )
                    }
            )
        }

        // 6) 颗粒噪点
        if (settings.grain > 0.01f) {
            GrainOverlay(settings.grain.coerceIn(0f, 1f))
        }

        content()
    }
}

@Composable
private fun GrainOverlay(strength: Float) {
    val grain = remember { GrainCache() }
    Box(
        Modifier
            .fillMaxSize()
            .drawBehind {
                drawPoints(
                    points = grain.points(size.width, size.height),
                    pointMode = PointMode.Points,
                    color = Color.White.copy(alpha = 0.055f * strength),
                    strokeWidth = 1.6f
                )
            }
    )
}

/** 噪点按画布尺寸缓存，避免每帧重新生成随机点。 */
private class GrainCache {
    private val random = Random(97)
    private var cachedW = -1f
    private var cachedH = -1f
    private var cached: List<Offset> = emptyList()

    fun points(w: Float, h: Float): List<Offset> {
        if (w != cachedW || h != cachedH) {
            cachedW = w
            cachedH = h
            cached = List(1300) { Offset(random.nextFloat() * w, random.nextFloat() * h) }
        }
        return cached
    }
}

@Composable
private fun rememberBackgroundBitmap(path: String?): androidx.compose.runtime.State<ImageBitmap?> {
    val context = LocalContext.current
    return produceState<ImageBitmap?>(initialValue = null, path) {
        value = withContext(Dispatchers.IO) { loadBackground(context, path) }
    }
}

private fun loadBackground(context: Context, path: String?): ImageBitmap? {
    if (path.isNullOrBlank()) return null
    return runCatching {
        val bitmap: Bitmap? = if (path.startsWith("/")) {
            val file = File(path)
            if (!file.exists()) null else decodeSampled { BitmapFactory.decodeFile(path, it) }
        } else {
            val uri = Uri.parse(path)
            context.contentResolver.openInputStream(uri)?.use { stream ->
                val bytes = stream.readBytes()
                decodeSampled { opts -> BitmapFactory.decodeByteArray(bytes, 0, bytes.size, opts) }
            }
        }
        bitmap?.asImageBitmap()
    }.getOrNull()
}

private fun decodeSampled(factory: (BitmapFactory.Options) -> Bitmap?): Bitmap? {
    val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
    factory(bounds)
    if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null
    var sample = 1
    val target = 1600
    var w = bounds.outWidth
    var h = bounds.outHeight
    while (w / sample > target && h / sample > target) {
        sample *= 2
        w = bounds.outWidth / sample
        h = bounds.outHeight / sample
    }
    val opts = BitmapFactory.Options().apply {
        inSampleSize = sample
        inPreferredConfig = Bitmap.Config.RGB_565
    }
    return factory(opts)
}

/** 把相册选择的图片复制到应用私有目录，避免 URI 授权过期后背景丢失。 */
fun persistBackgroundImage(context: Context, uri: Uri): String? = runCatching {
    val target = File(context.filesDir, "custom_background.img")
    context.contentResolver.openInputStream(uri)?.use { input ->
        target.outputStream().use { output -> input.copyTo(output) }
    }
    target.absolutePath
}.getOrNull()

/** Android 15 上 RenderEffect 高斯模糊可用性（ROM 限制时由调用方降级）。 */
fun blurSupported(): Boolean = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S
