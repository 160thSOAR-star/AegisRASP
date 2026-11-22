package com.rasp.detect

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import org.json.JSONObject
import kotlin.coroutines.coroutineContext

/**
 * RASP 检测引擎：ViewModel 只调用这里，不直接碰 JNI。
 *
 * 数据流：detect() → JavaProbes 补充证据 → native 异步流式返回证据 → 报告聚合结果。
 * 线程：全部在 Dispatchers.Default 上执行，主线程不会被阻塞。
 */
class RaspEngine(private val context: Context) {

    @Volatile
    private var running = false

    val isRunning: Boolean get() = running

    /**
     * 执行一次完整检测。
     * @param onEvidence 每完成一条证据即回调（在后台线程），用于 UI 流式渲染。
     */
    suspend fun detect(config: RaspConfig, onEvidence: (Evidence) -> Unit): RaspReport {
        if (!RaspNative.isAvailable()) {
            throw IllegalStateException("native 检测库加载失败（ABI 不受支持或 so 缺失）")
        }
        running = true
        try {
            return withContext(Dispatchers.Default) {
                ensureActive()
                // 1) Java 层补充证据（包列表多路径 / Binder 一致性）
                runCatching { JavaProbes(context).run() }.getOrDefault(emptyList()).forEach { ev ->
                    runCatching { RaspNative.submitEvidence(ev.toJson().toString()) }
                }
                ensureActive()

                // 2) 白名单
                val whitelistJson = WhitelistLoader.loadForNative(context)

                // 3) native 检测（阻塞直到完成，证据逐条回流）
                val sink = RaspNative.EvidenceSink { line ->
                    runCatching { Evidence.fromJson(JSONObject(line)) }.getOrNull()?.let(onEvidence)
                }
                val reportJson = RaspNative.runDetect(
                    config.toJsonString(),
                    whitelistJson,
                    config.weightSpec(),
                    context.filesDir.absolutePath,
                    sink
                )
                coroutineContext.ensureActive()
                RaspReport.fromJson(JSONObject(reportJson))
            }
        } finally {
            running = false
        }
    }

    fun cancel() {
        runCatching { RaspNative.cancelDetect() }
    }
}
