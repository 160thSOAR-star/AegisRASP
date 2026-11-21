package com.rasp.detect

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/**
 * 白名单数据模型（对应《生成要求》④-4 的标准 JSON 模板）。
 *
 * 语义：native 侧把每个数组元素当作「片段」做子串匹配，命中即豁免对应证据。
 */
data class WhitelistData(
    val mounts: List<String> = emptyList(),
    val processes: List<String> = emptyList(),
    val properties: List<String> = emptyList(),
    val kernel: List<String> = emptyList(),
    val oem: List<String> = emptyList()
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("schema", 1)
        put("version", 1)
        put("mounts", JSONArray(mounts))
        put("processes", JSONArray(processes))
        put("properties", JSONArray(properties))
        put("kernel", JSONArray(kernel))
        put("oem", JSONArray(oem))
    }

    fun merge(extra: WhitelistData): WhitelistData = WhitelistData(
        mounts = (mounts + extra.mounts).distinct(),
        processes = (processes + extra.processes).distinct(),
        properties = (properties + extra.properties).distinct(),
        kernel = (kernel + extra.kernel).distinct(),
        oem = (oem + extra.oem).distinct()
    )

    companion object {
        fun parse(text: String?): WhitelistData {
            if (text.isNullOrBlank()) return WhitelistData()
            return runCatching {
                val o = JSONObject(text)
                WhitelistData(
                    mounts = o.array("mounts"),
                    processes = o.array("processes"),
                    properties = o.array("properties"),
                    kernel = o.array("kernel"),
                    oem = o.array("oem")
                )
            }.getOrDefault(WhitelistData())
        }

        private fun JSONObject.array(key: String): List<String> {
            val arr = optJSONArray(key) ?: return emptyList()
            val out = ArrayList<String>(arr.length())
            for (i in 0 until arr.length()) {
                val v = arr.optString(i)
                if (v.isNotBlank()) out.add(v)
            }
            return out
        }
    }
}

/** 从 assets 读取默认白名单，并允许运行时叠加用户自定义条目。 */
object WhitelistLoader {
    const val ASSET_NAME = "whitelist_default.json"

    fun loadDefault(context: Context): WhitelistData = runCatching {
        context.assets.open(ASSET_NAME).bufferedReader().use { it.readText() }
    }.map { WhitelistData.parse(it) }.getOrDefault(WhitelistData())

    /** 返回给 native 的白名单 JSON 字符串。 */
    fun loadForNative(context: Context, extraJson: String? = null): String {
        val base = loadDefault(context)
        val extra = WhitelistData.parse(extraJson)
        return base.merge(extra).toJson().toString()
    }
}
