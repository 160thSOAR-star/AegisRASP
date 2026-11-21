package com.rasp.detect.ui

import com.rasp.detect.CheckCatalog
import com.rasp.detect.Evidence
import com.rasp.detect.RaspReport
import com.rasp.detect.RiskLevel

/** 检测生命周期状态：空闲 → 检测中 → 检测完成 / 检测失败。 */
enum class DetectPhase { IDLE, RUNNING, DONE, FAILED }

/** 屏幕级 UI 状态（由 ViewModel 单一持有，配置变更不丢失）。 */
data class RaspUiState(
    val phase: DetectPhase = DetectPhase.IDLE,
    val items: List<Evidence> = emptyList(),
    val report: RaspReport? = null,
    val progressDone: Int = 0,
    val progressTotal: Int = CheckCatalog.total,
    val error: String? = null,
    val startedAt: Long = 0L,
    val elapsedMs: Long = 0L
) {
    val score: Int get() = report?.score ?: 0
    val level: RiskLevel get() = report?.level ?: RiskLevel.fromScore(score)
    val confidence: Double get() = report?.confidence ?: 0.0
    val hitItems: List<Evidence> get() = items.filter { it.hit }
    val progress: Float
        get() = if (progressTotal <= 0) 0f
        else (progressDone.toFloat() / progressTotal).coerceIn(0f, 1f)
}

/** 设置页状态（含背景与雪花参数，全部持久化到 DataStore）。 */
data class AppSettings(
    val backgroundUri: String? = null,
    val backgroundOpacity: Float = 0.55f,
    val frost: Float = 0.45f,
    val vignette: Float = 0.45f,
    val grain: Float = 0.16f,
    val coldLight: Boolean = true,
    val blurRadius: Float = 14f,
    val snowEnabled: Boolean = true,
    val snowDensity: Float = 0.5f,
    val snowSize: Float = 0.5f,
    val snowSpeed: Float = 0.5f,
    val snowOpacity: Float = 0.65f,
    val accentIndex: Int = 0,
    val fastMode: Boolean = false,
    val sandboxEnabled: Boolean = true,
    val whitelistEnabled: Boolean = true,
    val disabledIds: Set<String> = emptySet(),
    val weightOverrides: Map<String, Int> = emptyMap()
) {
    companion object {
        val Accents = listOf("冷蓝", "青灰", "警示红")
    }
}
