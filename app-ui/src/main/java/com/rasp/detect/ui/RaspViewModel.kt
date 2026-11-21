package com.rasp.detect.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.rasp.detect.Evidence
import com.rasp.detect.RaspConfig
import com.rasp.detect.RaspEngine
import com.rasp.detect.RaspReport
import com.rasp.detect.ui.data.SettingsRepository
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * 检测状态与设置的唯一持有者。
 * ViewModel 生命周期跨越配置变更，所以旋转屏幕不会丢失检测结果。
 */
class RaspViewModel(application: Application) : AndroidViewModel(application) {

    private val engine = RaspEngine(application)
    private val repo = SettingsRepository(application)

    private val _state = MutableStateFlow(RaspUiState())
    val state: StateFlow<RaspUiState> = _state.asStateFlow()

    val settings: StateFlow<AppSettings> =
        repo.settings.stateIn(viewModelScope, SharingStarted.Eagerly, AppSettings())

    private var detectJob: Job? = null
    private var tickerJob: Job? = null

    fun startDetection() {
        if (_state.value.phase == DetectPhase.RUNNING) return
        val cfg = settings.value
        val config = RaspConfig(
            fastMode = cfg.fastMode,
            sandbox = cfg.sandboxEnabled,
            whitelistEnabled = cfg.whitelistEnabled,
            disabledIds = cfg.disabledIds,
            weightOverrides = cfg.weightOverrides
        )

        _state.update {
            it.copy(
                phase = DetectPhase.RUNNING,
                items = emptyList(),
                report = null,
                error = null,
                startedAt = System.currentTimeMillis(),
                elapsedMs = 0L,
                progressDone = 0
            )
        }

        tickerJob?.cancel()
        tickerJob = viewModelScope.launch {
            while (isActive && _state.value.phase == DetectPhase.RUNNING) {
                val start = _state.value.startedAt
                if (start > 0) {
                    _state.update { it.copy(elapsedMs = System.currentTimeMillis() - start) }
                }
                delay(120)
            }
        }

        detectJob = viewModelScope.launch {
            try {
                val report: RaspReport = engine.detect(config) { ev: Evidence ->
                    _state.update { s ->
                        val merged = if (s.items.any { it.id == ev.id }) s.items else s.items + ev
                        s.copy(items = merged, progressDone = merged.size)
                    }
                }
                _state.update {
                    it.copy(
                        phase = DetectPhase.DONE,
                        report = report,
                        items = if (report.items.isNotEmpty()) report.items else it.items,
                        progressDone = if (report.items.isNotEmpty()) report.items.size else it.progressDone
                    )
                }
            } catch (t: Throwable) {
                _state.update {
                    it.copy(
                        phase = DetectPhase.FAILED,
                        error = t.message ?: t.javaClass.simpleName
                    )
                }
            } finally {
                tickerJob?.cancel()
            }
        }
    }

    fun cancelDetection() {
        engine.cancel()
        detectJob?.cancel()
        tickerJob?.cancel()
        _state.update { it.copy(phase = DetectPhase.IDLE) }
    }

    fun resetToIdle() {
        _state.update {
            it.copy(
                phase = DetectPhase.IDLE,
                items = emptyList(),
                report = null,
                error = null,
                progressDone = 0
            )
        }
    }

    // ---------- 设置项透传 ----------
    fun setBackgroundUri(uri: String?) = viewModelScope.launch { repo.setBackgroundUri(uri) }
    fun setBackgroundOpacity(v: Float) = viewModelScope.launch { repo.setBackgroundOpacity(v) }
    fun setFrost(v: Float) = viewModelScope.launch { repo.setFrost(v) }
    fun setVignette(v: Float) = viewModelScope.launch { repo.setVignette(v) }
    fun setGrain(v: Float) = viewModelScope.launch { repo.setGrain(v) }
    fun setColdLight(v: Boolean) = viewModelScope.launch { repo.setColdLight(v) }
    fun setBlur(v: Float) = viewModelScope.launch { repo.setBlur(v) }
    fun setSnowEnabled(v: Boolean) = viewModelScope.launch { repo.setSnowEnabled(v) }
    fun setSnowDensity(v: Float) = viewModelScope.launch { repo.setSnowDensity(v) }
    fun setSnowSize(v: Float) = viewModelScope.launch { repo.setSnowSize(v) }
    fun setSnowSpeed(v: Float) = viewModelScope.launch { repo.setSnowSpeed(v) }
    fun setSnowOpacity(v: Float) = viewModelScope.launch { repo.setSnowOpacity(v) }
    fun setAccent(index: Int) = viewModelScope.launch { repo.setAccent(index) }
    fun setFastMode(v: Boolean) = viewModelScope.launch { repo.setFastMode(v) }
    fun setSandbox(v: Boolean) = viewModelScope.launch { repo.setSandbox(v) }
    fun setWhitelist(v: Boolean) = viewModelScope.launch { repo.setWhitelist(v) }
    fun toggleCheck(id: String, enabled: Boolean) = viewModelScope.launch { repo.toggleCheck(id, enabled) }
    fun setWeight(id: String, weight: Int) = viewModelScope.launch { repo.setWeight(id, weight) }
    fun resetSettings() = viewModelScope.launch { repo.resetAll() }
}
