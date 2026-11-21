package com.rasp.detect.ui.data

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.floatPreferencesKey
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.rasp.detect.ui.AppSettings
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private val Context.aegisDataStore: DataStore<Preferences> by preferencesDataStore(name = "aegis_settings")

/**
 * 背景 / 雪花 / 主题 / 检测配置的持久化（DataStore Preferences）。
 * 背景配置在旋转屏幕、进程重启后均保持。
 */
class SettingsRepository(private val context: Context) {

    private object Keys {
        val BG_URI = stringPreferencesKey("bg_uri")
        val BG_OPACITY = floatPreferencesKey("bg_opacity")
        val FROST = floatPreferencesKey("frost")
        val VIGNETTE = floatPreferencesKey("vignette")
        val GRAIN = floatPreferencesKey("grain")
        val COLD_LIGHT = booleanPreferencesKey("cold_light")
        val BLUR = floatPreferencesKey("blur")
        val SNOW_ENABLED = booleanPreferencesKey("snow_enabled")
        val SNOW_DENSITY = floatPreferencesKey("snow_density")
        val SNOW_SIZE = floatPreferencesKey("snow_size")
        val SNOW_SPEED = floatPreferencesKey("snow_speed")
        val SNOW_OPACITY = floatPreferencesKey("snow_opacity")
        val ACCENT = intPreferencesKey("accent_index")
        val FAST_MODE = booleanPreferencesKey("fast_mode")
        val SANDBOX = booleanPreferencesKey("sandbox")
        val WHITELIST = booleanPreferencesKey("whitelist")
        val DISABLED = stringPreferencesKey("disabled_ids")
        val WEIGHTS = stringPreferencesKey("weight_overrides")
    }

    val settings: Flow<AppSettings> = context.aegisDataStore.data.map { p ->
        AppSettings(
            backgroundUri = p[Keys.BG_URI],
            backgroundOpacity = p[Keys.BG_OPACITY] ?: 0.55f,
            frost = p[Keys.FROST] ?: 0.45f,
            vignette = p[Keys.VIGNETTE] ?: 0.45f,
            grain = p[Keys.GRAIN] ?: 0.16f,
            coldLight = p[Keys.COLD_LIGHT] ?: true,
            blurRadius = p[Keys.BLUR] ?: 14f,
            snowEnabled = p[Keys.SNOW_ENABLED] ?: true,
            snowDensity = p[Keys.SNOW_DENSITY] ?: 0.5f,
            snowSize = p[Keys.SNOW_SIZE] ?: 0.5f,
            snowSpeed = p[Keys.SNOW_SPEED] ?: 0.5f,
            snowOpacity = p[Keys.SNOW_OPACITY] ?: 0.65f,
            accentIndex = p[Keys.ACCENT] ?: 0,
            fastMode = p[Keys.FAST_MODE] ?: false,
            sandboxEnabled = p[Keys.SANDBOX] ?: true,
            whitelistEnabled = p[Keys.WHITELIST] ?: true,
            disabledIds = parseSet(p[Keys.DISABLED]),
            weightOverrides = parseWeights(p[Keys.WEIGHTS])
        )
    }

    suspend fun setBackgroundUri(uri: String?) = edit { it[Keys.BG_URI] = uri ?: "" }
    suspend fun setBackgroundOpacity(v: Float) = edit { it[Keys.BG_OPACITY] = v }
    suspend fun setFrost(v: Float) = edit { it[Keys.FROST] = v }
    suspend fun setVignette(v: Float) = edit { it[Keys.VIGNETTE] = v }
    suspend fun setGrain(v: Float) = edit { it[Keys.GRAIN] = v }
    suspend fun setColdLight(v: Boolean) = edit { it[Keys.COLD_LIGHT] = v }
    suspend fun setBlur(v: Float) = edit { it[Keys.BLUR] = v }
    suspend fun setSnowEnabled(v: Boolean) = edit { it[Keys.SNOW_ENABLED] = v }
    suspend fun setSnowDensity(v: Float) = edit { it[Keys.SNOW_DENSITY] = v }
    suspend fun setSnowSize(v: Float) = edit { it[Keys.SNOW_SIZE] = v }
    suspend fun setSnowSpeed(v: Float) = edit { it[Keys.SNOW_SPEED] = v }
    suspend fun setSnowOpacity(v: Float) = edit { it[Keys.SNOW_OPACITY] = v }
    suspend fun setAccent(index: Int) = edit { it[Keys.ACCENT] = index }
    suspend fun setFastMode(v: Boolean) = edit { it[Keys.FAST_MODE] = v }
    suspend fun setSandbox(v: Boolean) = edit { it[Keys.SANDBOX] = v }
    suspend fun setWhitelist(v: Boolean) = edit { it[Keys.WHITELIST] = v }

    suspend fun toggleCheck(id: String, enabled: Boolean) = edit { prefs ->
        val cur = parseSet(prefs[Keys.DISABLED]).toMutableSet()
        if (enabled) cur.remove(id) else cur.add(id)
        prefs[Keys.DISABLED] = cur.joinToString(",")
    }

    suspend fun setWeight(id: String, weight: Int) = edit { prefs ->
        val cur = parseWeights(prefs[Keys.WEIGHTS]).toMutableMap()
        if (weight > 0) cur[id] = weight else cur.remove(id)
        prefs[Keys.WEIGHTS] = cur.entries.joinToString(";") { "${it.key}=${it.value}" }
    }

    suspend fun resetAll() {
        context.aegisDataStore.edit { it.clear() }
    }

    private suspend fun edit(block: (androidx.datastore.preferences.core.MutablePreferences) -> Unit) {
        context.aegisDataStore.edit { prefs -> block(prefs) }
    }

    private fun parseSet(raw: String?): Set<String> =
        if (raw.isNullOrBlank()) emptySet()
        else raw.split(',').map { it.trim() }.filter { it.isNotEmpty() }.toSet()

    private fun parseWeights(raw: String?): Map<String, Int> {
        if (raw.isNullOrBlank()) return emptyMap()
        return raw.split(';').mapNotNull { entry ->
            val parts = entry.split('=')
            if (parts.size != 2) return@mapNotNull null
            val w = parts[1].toIntOrNull() ?: return@mapNotNull null
            parts[0] to w
        }.toMap()
    }
}
