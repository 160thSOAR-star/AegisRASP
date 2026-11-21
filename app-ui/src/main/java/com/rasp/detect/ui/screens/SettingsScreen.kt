package com.rasp.detect.ui.screens

import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.DeleteSweep
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Info
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Slider
import androidx.compose.material3.SliderDefaults
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.rasp.detect.CheckCatalog
import com.rasp.detect.RaspNative
import com.rasp.detect.ReportExporter
import com.rasp.detect.WhitelistLoader
import com.rasp.detect.ui.AppSettings
import com.rasp.detect.ui.RaspViewModel
import com.rasp.detect.ui.components.GlassCard
import com.rasp.detect.ui.components.InfoRow
import com.rasp.detect.ui.components.SectionHeader
import com.rasp.detect.ui.components.TagChip
import com.rasp.detect.ui.export.ExportManager
import com.rasp.detect.ui.theme.Amber
import com.rasp.detect.ui.theme.ColdBlue
import com.rasp.detect.ui.theme.Cyan
import com.rasp.detect.ui.theme.TextMuted
import com.rasp.detect.ui.theme.WarnRed
import com.rasp.detect.ui.theme.gradeColor

/** 设置页：检测项开关、自定义权重、背景、雪花、主题、白名单、缓存、关于。 */
@Composable
fun SettingsScreen(
    settings: AppSettings,
    vm: RaspViewModel
) {
    val context = LocalContext.current
    val exportManager = remember { ExportManager(context) }
    var showWhitelist by remember { mutableStateOf(false) }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 10.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "设置",
                    style = MaterialTheme.typography.headlineSmall,
                    modifier = Modifier.padding(start = 4.dp)
                )
            }
        }

        // ---------------- 检测配置 ----------------
        item {
            GlassCard(modifier = Modifier.fillMaxWidth(), corner = 22.dp) {
                SectionHeader(title = "检测调度", trailing = "分级执行")
                SwitchRow(
                    label = "快速模式",
                    description = "跳过高开销项（网络时延、跨进程枚举），耗时 < 2s",
                    checked = settings.fastMode,
                    onCheckedChange = vm::setFastMode
                )
                SwitchRow(
                    label = "clone3 沙箱",
                    description = "创建无 Java 运行时的子进程做跨视图比对",
                    checked = settings.sandboxEnabled,
                    onCheckedChange = vm::setSandbox
                )
                SwitchRow(
                    label = "白名单豁免",
                    description = "命中白名单的系统/OEM 特征不计入打分",
                    checked = settings.whitelistEnabled,
                    onCheckedChange = vm::setWhitelist
                )
            }
        }

        // ---------------- 检测项开关 ----------------
        item {
            GlassCard(modifier = Modifier.fillMaxWidth(), corner = 22.dp) {
                SectionHeader(
                    title = "检测项开关",
                    trailing = "已启用 ${CheckCatalog.total - settings.disabledIds.size}/${CheckCatalog.total}"
                )
                CheckCatalog.entries.groupBy { it.category }.forEach { (category, entries) ->
                    Text(
                        text = ReportExporter.categoryLabel(category),
                        style = MaterialTheme.typography.labelSmall,
                        color = Cyan,
                        modifier = Modifier.padding(top = 14.dp, bottom = 2.dp)
                    )
                    entries.forEach { meta ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 6.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(Modifier.weight(1f)) {
                                Text(
                                    text = meta.name,
                                    style = MaterialTheme.typography.bodySmall
                                )
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Text(
                                        text = meta.id,
                                        style = MaterialTheme.typography.labelSmall,
                                        color = TextMuted
                                    )
                                    TagChip(
                                        text = meta.grade.label,
                                        color = gradeColor(meta.grade.key),
                                        modifier = Modifier.padding(start = 6.dp)
                                    )
                                    Text(
                                        text = " · 开销 ${meta.cost}",
                                        style = MaterialTheme.typography.labelSmall,
                                        color = TextMuted
                                    )
                                }
                            }
                            Switch(
                                checked = !settings.disabledIds.contains(meta.id),
                                onCheckedChange = { vm.toggleCheck(meta.id, it) },
                                colors = androidx.compose.material3.SwitchDefaults.colors(
                                    checkedThumbColor = Color(0xFF04121A),
                                    checkedTrackColor = Cyan
                                )
                            )
                        }
                    }
                }
            }
        }

        // ---------------- 自定义权重 ----------------
        item {
            GlassCard(modifier = Modifier.fillMaxWidth(), corner = 22.dp) {
                SectionHeader(title = "自定义权重", trailing = "0 = 使用等级默认值")
                Text(
                    text = "默认权重：强证据 30 / 间接证据 10 / 弱线索 3（同类叠加有 0.7^n 衰减）。" +
                        "拖动滑块可覆盖单项权重，保存后下次检测生效。",
                    style = MaterialTheme.typography.labelSmall,
                    color = TextMuted,
                    modifier = Modifier.padding(bottom = 4.dp)
                )
                CheckCatalog.entries.forEach { meta ->
                    val current = settings.weightOverrides[meta.id] ?: meta.grade.weight
                    var local by remember(meta.id, current) { mutableFloatStateOf(current.toFloat()) }
                    Column(Modifier.padding(top = 10.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Text(
                                text = "${meta.id} · ${meta.name}",
                                style = MaterialTheme.typography.labelSmall,
                                color = TextMuted,
                                maxLines = 1
                            )
                            Text(
                                text = local.toInt().toString(),
                                style = MaterialTheme.typography.labelSmall,
                                color = Amber
                            )
                        }
                        Slider(
                            value = local,
                            onValueChange = { local = it },
                            onValueChangeFinished = { vm.setWeight(meta.id, local.toInt()) },
                            valueRange = 0f..60f,
                            colors = SliderDefaults.colors(
                                thumbColor = Amber,
                                activeTrackColor = Amber.copy(alpha = 0.7f),
                                inactiveTrackColor = Color(0xFF1A2636)
                            )
                        )
                    }
                }
            }
        }

        // ---------------- 背景设置 ----------------
        item {
            BackgroundPanel(
                settings = settings,
                onPickImage = vm::setBackgroundUri,
                onClearImage = { vm.setBackgroundUri(null) },
                onOpacity = vm::setBackgroundOpacity,
                onFrost = vm::setFrost,
                onVignette = vm::setVignette,
                onGrain = vm::setGrain,
                onBlur = vm::setBlur,
                onColdLight = vm::setColdLight,
                onReset = {
                    vm.setBackgroundOpacity(0.55f)
                    vm.setFrost(0.45f)
                    vm.setVignette(0.45f)
                    vm.setGrain(0.16f)
                    vm.setBlur(14f)
                }
            )
        }

        // ---------------- 雪花动画 ----------------
        item {
            GlassCard(modifier = Modifier.fillMaxWidth(), corner = 22.dp) {
                SectionHeader(title = "雪花动画", trailing = "Canvas 自绘")
                SwitchRow(
                    label = "启用全屏雪花",
                    description = "页面不可见时自动暂停；低端设备自动降采样",
                    checked = settings.snowEnabled,
                    onCheckedChange = vm::setSnowEnabled
                )
                LabeledSlider(
                    label = "密度",
                    value = settings.snowDensity,
                    text = "${(settings.snowDensity * 100).toInt()}%",
                    onChange = vm::setSnowDensity
                )
                LabeledSlider(
                    label = "雪花大小",
                    value = settings.snowSize,
                    text = "${(settings.snowSize * 100).toInt()}%",
                    onChange = vm::setSnowSize
                )
                LabeledSlider(
                    label = "下落速度",
                    value = settings.snowSpeed,
                    text = "${(settings.snowSpeed * 100).toInt()}%",
                    onChange = vm::setSnowSpeed
                )
                LabeledSlider(
                    label = "透明度",
                    value = settings.snowOpacity,
                    text = "${(settings.snowOpacity * 100).toInt()}%",
                    onChange = vm::setSnowOpacity
                )
            }
        }

        // ---------------- 主题 ----------------
        item {
            GlassCard(modifier = Modifier.fillMaxWidth(), corner = 22.dp) {
                SectionHeader(title = "主题强调色")
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    listOf(
                        "冷蓝" to ColdBlue,
                        "青灰" to Cyan,
                        "警示红" to WarnRed
                    ).forEachIndexed { index, (name, color) ->
                        val selected = settings.accentIndex == index
                        Column(
                            modifier = Modifier
                                .clip(RoundedCornerShape(14.dp))
                                .background(
                                    if (selected) color.copy(alpha = 0.18f)
                                    else Color(0xFF111C2A)
                                )
                                .clickable { vm.setAccent(index) }
                                .padding(horizontal = 16.dp, vertical = 10.dp),
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            Text(text = name, style = MaterialTheme.typography.labelSmall, color = color)
                            Spacer(Modifier.height(4.dp))
                            Text(
                                text = if (selected) "已选中" else "选择",
                                style = MaterialTheme.typography.labelSmall,
                                color = TextMuted,
                                fontSize = 9.sp
                            )
                        }
                    }
                }
            }
        }

        // ---------------- 白名单 / 缓存 ----------------
        item {
            GlassCard(modifier = Modifier.fillMaxWidth(), corner = 22.dp) {
                SectionHeader(title = "白名单与数据")
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(14.dp))
                        .background(Color(0xFF111C2A))
                        .clickable { showWhitelist = true }
                        .padding(vertical = 12.dp),
                    horizontalArrangement = Arrangement.Center,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = Icons.Filled.Description,
                        contentDescription = null,
                        tint = Cyan,
                        modifier = Modifier
                            .size(16.dp)
                            .padding(end = 4.dp)
                    )
                    Text(
                        text = "查看白名单模板",
                        style = MaterialTheme.typography.labelSmall,
                        color = Color(0xFFBFD6FF)
                    )
                }
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 10.dp)
                        .clip(RoundedCornerShape(14.dp))
                        .background(Color(0xFF111C2A))
                        .clickable {
                            val removed = exportManager.clearCache()
                            Toast.makeText(context, "已清理 $removed 个导出文件", Toast.LENGTH_SHORT).show()
                        }
                        .padding(vertical = 12.dp),
                    horizontalArrangement = Arrangement.Center,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = Icons.Filled.DeleteSweep,
                        contentDescription = null,
                        tint = Amber,
                        modifier = Modifier
                            .size(16.dp)
                            .padding(end = 4.dp)
                    )
                    Text(
                        text = "清理导出缓存",
                        style = MaterialTheme.typography.labelSmall,
                        color = Color(0xFFBFD6FF)
                    )
                }
            }
        }

        // ---------------- 关于 ----------------
        item {
            GlassCard(modifier = Modifier.fillMaxWidth(), corner = 22.dp, tint = 0.6f) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Filled.Info,
                        contentDescription = null,
                        tint = Cyan,
                        modifier = Modifier.size(18.dp)
                    )
                    Text(
                        text = "关于",
                        style = MaterialTheme.typography.titleSmall,
                        modifier = Modifier.padding(start = 6.dp)
                    )
                }
                InfoRow("应用版本", com.rasp.detect.ui.BuildConfig.VERSION_NAME)
                InfoRow("Native 引擎", RaspNative.versionOrNull() ?: "未加载")
                InfoRow("检测项总数", "${CheckCatalog.total} 项")
                InfoRow("权限要求", "无（普通非 Root 应用）")
                InfoRow("网络访问", "无（全部本地检测）")
                Text(
                    text = "本应用仅做痕迹检测与证据采集，不实现任何绕过、攻击或修改 KernelSU 等环境的行为；" +
                        "不使用 SafetyNet / Play Integrity 等远程校验。",
                    style = MaterialTheme.typography.labelSmall,
                    color = TextMuted,
                    modifier = Modifier.padding(top = 8.dp)
                )
            }
        }

        item { Spacer(Modifier.height(30.dp)) }
    }

    if (showWhitelist) {
        val json = remember {
            runCatching { WhitelistLoader.loadDefault(context).toJson().toString(2) }
                .getOrDefault("{}")
        }
        AlertDialog(
            onDismissRequest = { showWhitelist = false },
            title = { Text("白名单模板") },
            text = {
                Column(
                    Modifier
                        .height(420.dp)
                        .fillMaxWidth()
                ) {
                    LazyColumn {
                        item {
                            Text(
                                text = json,
                                style = MaterialTheme.typography.bodySmall.copy(fontSize = 10.sp),
                                color = Color(0xFF9FC3DE),
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .background(Color(0xFF0A111A), RoundedCornerShape(10.dp))
                                    .padding(10.dp)
                            )
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { showWhitelist = false }) { Text("关闭") }
            }
        )
    }
}
