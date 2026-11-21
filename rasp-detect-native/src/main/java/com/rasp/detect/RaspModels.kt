package com.rasp.detect

import org.json.JSONArray
import org.json.JSONObject

/** 证据等级：与 native 层 razor_grade_t 一一对应。 */
enum class EvidenceGrade(val key: String, val label: String, val weight: Int) {
    STRONG("strong", "强证据", 30),
    INDIRECT("indirect", "间接证据", 10),
    WEAK("weak", "弱线索", 3);

    companion object {
        fun from(key: String?): EvidenceGrade = when (key) {
            "strong" -> STRONG
            "indirect" -> INDIRECT
            else -> WEAK
        }
    }
}

/** 风险等级阈值（见《生成要求》⑥-2）。 */
enum class RiskLevel(val key: String, val label: String, val summary: String) {
    SAFE("safe", "安全", "未发现明显 Root / KernelSU 痕迹"),
    SUSPICIOUS("suspicious", "可疑", "存在异常特征，建议进一步人工确认"),
    HIGH("high", "高风险", "高度疑似 KernelSU 隐藏环境");

    companion object {
        fun fromScore(score: Int): RiskLevel = when {
            score > 50 -> HIGH
            score > 20 -> SUSPICIOUS
            else -> SAFE
        }

        fun from(key: String?): RiskLevel = when (key) {
            "high" -> HIGH
            "suspicious" -> SUSPICIOUS
            else -> SAFE
        }
    }
}

/** 单条检测证据，与 native `rasp_evidence_t` 序列化结果对应。 */
data class Evidence(
    val id: String,
    val name: String,
    val category: String,
    val grade: EvidenceGrade,
    val confidence: Double,
    val hit: Boolean,
    val available: Boolean,
    val rawText: String,
    val error: String,
    val timestamp: Long
) {
    val rawPretty: String
        get() = runCatching {
            when {
                rawText.startsWith("{") -> JSONObject(rawText).toString(2)
                rawText.startsWith("[") -> JSONArray(rawText).toString(2)
                else -> rawText
            }
        }.getOrDefault(rawText)

    fun toJson(): JSONObject = JSONObject().apply {
        put("id", id)
        put("name", name)
        put("category", category)
        put("grade", grade.key)
        put("confidence", confidence)
        put("hit", hit)
        put("available", available)
        put("raw", rawText)
        put("error", error)
        put("timestamp", timestamp)
    }

    companion object {
        fun fromJson(o: JSONObject): Evidence = Evidence(
            id = o.optString("id"),
            name = o.optString("name"),
            category = o.optString("category"),
            grade = EvidenceGrade.from(o.optString("grade")),
            confidence = o.optDouble("confidence", 0.0),
            hit = o.optBoolean("hit", false),
            available = o.optBoolean("available", true),
            rawText = o.optString("raw"),
            error = o.optString("error"),
            timestamp = o.optLong("timestamp", 0L)
        )
    }
}

data class Counts(
    val strong: Int,
    val indirect: Int,
    val weak: Int,
    val hits: Int,
    val available: Int,
    val total: Int
)

data class DeviceInfo(
    val sdk: String,
    val release: String,
    val model: String,
    val abi: String,
    val buildTags: String,
    val pid: Long,
    val uid: Long
)

data class ConfigEcho(
    val fastMode: Boolean,
    val sandbox: Boolean,
    val whitelist: Boolean,
    val kernelProbe: Boolean
)

/** 完整检测报告，与 native `rasp_build_report_json` 输出一一对应。 */
data class RaspReport(
    val score: Int,
    val level: RiskLevel,
    val confidence: Double,
    val durationMs: Long,
    val startedAt: Long,
    val finishedAt: Long,
    val counts: Counts,
    val device: DeviceInfo,
    val config: ConfigEcho,
    val antiHookHit: Boolean,
    val items: List<Evidence>
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("schema", 1)
        put("score", score)
        put("level", level.key)
        put("confidence", confidence)
        put("durationMs", durationMs)
        put("startedAt", startedAt)
        put("finishedAt", finishedAt)
        put("counts", JSONObject().apply {
            put("strong", counts.strong)
            put("indirect", counts.indirect)
            put("weak", counts.weak)
            put("hits", counts.hits)
            put("available", counts.available)
            put("total", counts.total)
        })
        put("device", JSONObject().apply {
            put("sdk", device.sdk)
            put("release", device.release)
            put("model", device.model)
            put("abi", device.abi)
            put("buildTags", device.buildTags)
            put("pid", device.pid)
            put("uid", device.uid)
        })
        put("config", JSONObject().apply {
            put("fastMode", config.fastMode)
            put("sandbox", config.sandbox)
            put("whitelist", config.whitelist)
            put("kernelProbe", config.kernelProbe)
        })
        put("antiHook", JSONObject().put("hit", antiHookHit))
        put("items", JSONArray().apply { items.forEach { put(it.toJson()) } })
    }

    /** 命中且可用的证据，按证据等级与置信度排序。 */
    fun sortedItems(): List<Evidence> = items.sortedWith(
        compareByDescending<Evidence> { it.hit }
            .thenByDescending { it.grade.ordinal }
            .thenByDescending { it.confidence }
    )

    companion object {
        fun fromJson(o: JSONObject): RaspReport {
            val counts = o.optJSONObject("counts")
            val device = o.optJSONObject("device")
            val config = o.optJSONObject("config")
            val antiHook = o.optJSONObject("antiHook")?.optBoolean("hit") ?: false
            val items = mutableListOf<Evidence>()
            val arr = o.optJSONArray("items")
            if (arr != null) {
                for (i in 0 until arr.length()) {
                    arr.optJSONObject(i)?.let { items.add(Evidence.fromJson(it)) }
                }
            }
            return RaspReport(
                score = o.optInt("score", 0),
                level = RiskLevel.from(o.optString("level")),
                confidence = o.optDouble("confidence", 0.0),
                durationMs = o.optLong("durationMs", 0L),
                startedAt = o.optLong("startedAt", 0L),
                finishedAt = o.optLong("finishedAt", 0L),
                counts = Counts(
                    strong = counts?.optInt("strong") ?: 0,
                    indirect = counts?.optInt("indirect") ?: 0,
                    weak = counts?.optInt("weak") ?: 0,
                    hits = counts?.optInt("hits") ?: 0,
                    available = counts?.optInt("available") ?: 0,
                    total = counts?.optInt("total") ?: 0
                ),
                device = DeviceInfo(
                    sdk = device?.optString("sdk").orEmpty(),
                    release = device?.optString("release").orEmpty(),
                    model = device?.optString("model").orEmpty(),
                    abi = device?.optString("abi").orEmpty(),
                    buildTags = device?.optString("buildTags").orEmpty(),
                    pid = device?.optLong("pid") ?: 0L,
                    uid = device?.optLong("uid") ?: 0L
                ),
                config = ConfigEcho(
                    fastMode = config?.optBoolean("fastMode") ?: false,
                    sandbox = config?.optBoolean("sandbox") ?: true,
                    whitelist = config?.optBoolean("whitelist") ?: true,
                    kernelProbe = config?.optBoolean("kernelProbe") ?: false
                ),
                antiHookHit = antiHook,
                items = items
            )
        }
    }
}

/** 检测配置：UI 设置页 ↔ ViewModel ↔ Engine ↔ native 的单一载体。 */
data class RaspConfig(
    val fastMode: Boolean = false,
    val sandbox: Boolean = true,
    val whitelistEnabled: Boolean = true,
    val disabledIds: Set<String> = emptySet(),
    val weightOverrides: Map<String, Int> = emptyMap(),
    val timeoutMs: Long = 8000L
) {
    fun toJsonString(): String = JSONObject().apply {
        put("fastMode", fastMode)
        put("sandbox", sandbox)
        put("whitelist", whitelistEnabled)
        put("timeoutMs", timeoutMs)
        put("disabled", JSONArray().apply { disabledIds.sorted().forEach { put(it) } })
    }.toString()

    fun weightSpec(): String = weightOverrides.entries
        .filter { it.value > 0 }
        .joinToString(";") { "${it.key}=${it.value}" }
}
