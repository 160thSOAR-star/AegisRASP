package com.rasp.detect.ui

import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.animation.Crossfade
import androidx.compose.animation.core.tween
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.rasp.detect.RaspReport
import com.rasp.detect.ui.components.AegisBackground
import com.rasp.detect.ui.components.ReportSheet
import com.rasp.detect.ui.components.SnowfallLayer
import com.rasp.detect.ui.export.ExportManager
import com.rasp.detect.ui.screens.AboutScreen
import com.rasp.detect.ui.screens.DashboardScreen
import com.rasp.detect.ui.screens.SettingsScreen
import com.rasp.detect.ui.theme.AegisTheme
import com.rasp.detect.ui.theme.Cyan
import com.rasp.detect.ui.theme.TextMuted

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            val vm: RaspViewModel = viewModel()
            val settings by vm.settings.collectAsStateWithLifecycle()
            val state by vm.state.collectAsStateWithLifecycle()

            AegisTheme(accentIndex = settings.accentIndex) {
                AegisApp(state = state, settings = settings, vm = vm)
            }
        }
    }
}

/** 底部导航的三个页面。 */
private enum class AegisTab(val label: String, val icon: ImageVector) {
    TEST("测试", Icons.Filled.Security),
    SETTINGS("设置", Icons.Filled.Settings),
    ABOUT("关于", Icons.Filled.Info)
}

/**
 * 应用根容器：背景层 → 雪花层 → 内容层 → 底部导航。
 * 雪花层位于内容层之下，不拦截任何触摸事件。
 */
@Composable
private fun AegisApp(
    state: RaspUiState,
    settings: AppSettings,
    vm: RaspViewModel
) {
    val context = LocalContext.current
    val exportManager = remember { ExportManager(context) }
    var tab by rememberSaveable { mutableStateOf(AegisTab.TEST) }
    var showReport by rememberSaveable { mutableStateOf(false) }

    fun exportReport(format: ExportManager.Format) {
        val report: RaspReport = state.report ?: run {
            Toast.makeText(context, "请先完成一次检测", Toast.LENGTH_SHORT).show()
            return
        }
        runCatching { exportManager.writeReport(report, format) }
            .onSuccess { uri ->
                Toast.makeText(context, "已导出：${format.name}", Toast.LENGTH_SHORT).show()
                if (format == ExportManager.Format.HTML) exportManager.openHtml(uri)
            }
            .onFailure {
                Toast.makeText(context, "导出失败：${it.message}", Toast.LENGTH_SHORT).show()
            }
    }

    fun shareReport() {
        val report = state.report ?: run {
            Toast.makeText(context, "请先完成一次检测", Toast.LENGTH_SHORT).show()
            return
        }
        runCatching { exportManager.writeReport(report, ExportManager.Format.HTML) }
            .onSuccess { uri -> exportManager.share(uri, "text/html", "Aegis RASP 检测报告") }
            .onFailure {
                Toast.makeText(context, "分享失败：${it.message}", Toast.LENGTH_SHORT).show()
            }
    }

    AegisBackground(settings = settings, modifier = Modifier.fillMaxSize()) {
        SnowfallLayer(
            enabled = settings.snowEnabled,
            density = settings.snowDensity,
            sizeScale = settings.snowSize,
            speedScale = settings.snowSpeed,
            opacity = settings.snowOpacity
        )

        Column(Modifier.fillMaxSize()) {
            Box(Modifier.weight(1f)) {
                Crossfade(
                    targetState = tab,
                    animationSpec = tween(durationMillis = 280),
                    label = "tab"
                ) { current ->
                    when (current) {
                        AegisTab.TEST -> DashboardScreen(
                            state = state,
                            settings = settings,
                            onStart = vm::startDetection,
                            onCancel = vm::cancelDetection,
                            onPreviewReport = { showReport = true },
                            onExport = { format -> exportReport(format) },
                            onShare = { shareReport() },
                            onDismissDiagnostic = vm::dismissDiagnostic
                        )

                        AegisTab.SETTINGS -> SettingsScreen(settings = settings, vm = vm)
                        AegisTab.ABOUT -> AboutScreen()
                    }
                }
            }
            AegisBottomBar(current = tab, onSelect = { tab = it })
        }

        val report = state.report
        if (showReport && report != null) {
            ReportSheet(
                report = report,
                onDismiss = { showReport = false },
                onExport = { format -> exportReport(format) },
                onShare = { shareReport() },
                onCopyEvidence = { ev ->
                    exportManager.copyToClipboard("Aegis Evidence ${ev.id}", ev.rawPretty)
                    Toast.makeText(context, "已复制 ${ev.id} 原始证据", Toast.LENGTH_SHORT).show()
                }
            )
        }
    }

    // 检测失败的提示（避免静默）
    LaunchedEffect(state.phase, state.error) {
        if (state.phase == DetectPhase.FAILED && state.error != null) {
            Toast.makeText(context, "检测失败：${state.error}", Toast.LENGTH_LONG).show()
        }
    }
}

/** 底部选择栏：测试 / 设置 / 关于。 */
@Composable
private fun AegisBottomBar(current: AegisTab, onSelect: (AegisTab) -> Unit) {
    Column(Modifier.navigationBarsPadding()) {
        HorizontalDivider(color = Color(0x332A3A4D))
        NavigationBar(
            containerColor = Color(0xE60A111A),
            tonalElevation = 0.dp,
            contentColor = TextMuted
        ) {
            AegisTab.entries.forEach { item ->
                NavigationBarItem(
                    selected = current == item,
                    onClick = { onSelect(item) },
                    icon = { Icon(imageVector = item.icon, contentDescription = item.label) },
                    label = {
                        Text(text = item.label, style = MaterialTheme.typography.labelSmall)
                    },
                    colors = NavigationBarItemDefaults.colors(
                        selectedIconColor = Cyan,
                        selectedTextColor = Cyan,
                        indicatorColor = Cyan.copy(alpha = 0.14f),
                        unselectedIconColor = TextMuted,
                        unselectedTextColor = TextMuted
                    )
                )
            }
        }
    }
}
