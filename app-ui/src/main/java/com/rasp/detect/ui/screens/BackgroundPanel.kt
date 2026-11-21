package com.rasp.detect.ui.screens

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Wallpaper
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Slider
import androidx.compose.material3.SliderDefaults
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.rasp.detect.ui.AppSettings
import com.rasp.detect.ui.components.GlassCard
import com.rasp.detect.ui.components.SectionHeader
import com.rasp.detect.ui.components.persistBackgroundImage
import com.rasp.detect.ui.theme.Cyan
import com.rasp.detect.ui.theme.TextMuted

/**
 * 背景设置面板：导入本地图片 + 透明度/质感/暗角/颗粒/冷光/模糊实时调节。
 * 所有参数即时生效（Compose 状态驱动），并通过 DataStore 持久化。
 */
@Composable
fun BackgroundPanel(
    settings: AppSettings,
    onPickImage: (String) -> Unit,
    onClearImage: () -> Unit,
    onOpacity: (Float) -> Unit,
    onFrost: (Float) -> Unit,
    onVignette: (Float) -> Unit,
    onGrain: (Float) -> Unit,
    onBlur: (Float) -> Unit,
    onColdLight: (Boolean) -> Unit,
    onReset: () -> Unit
) {
    val context = LocalContext.current
    val picker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.PickVisualMedia()
    ) { uri ->
        if (uri != null) {
            persistBackgroundImage(context, uri)?.let(onPickImage)
        }
    }

    GlassCard(modifier = Modifier.fillMaxWidth(), corner = 22.dp) {
        SectionHeader(title = "背景系统", trailing = if (settings.backgroundUri != null) "已导入图片" else "内置渐变")

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 4.dp),
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            PanelButton(
                text = if (settings.backgroundUri == null) "导入本地图片" else "更换图片",
                icon = { Icon(Icons.Filled.Wallpaper, null, tint = Cyan, modifier = Modifier.padding(end = 6.dp)) },
                modifier = Modifier.weight(1f)
            ) {
                picker.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly))
            }
            PanelButton(
                text = "重置",
                icon = { Icon(Icons.Filled.Delete, null, tint = TextMuted, modifier = Modifier.padding(end = 6.dp)) },
                modifier = Modifier.weight(0.55f)
            ) {
                onClearImage()
                onReset()
            }
        }

        LabeledSlider(
            label = "背景透明度",
            value = settings.backgroundOpacity,
            text = "${(settings.backgroundOpacity * 100).toInt()}%",
            onChange = onOpacity
        )
        LabeledSlider(
            label = "雾面磨砂强度",
            value = settings.frost,
            text = "${(settings.frost * 100).toInt()}%",
            onChange = onFrost
        )
        LabeledSlider(
            label = "暗角强度",
            value = settings.vignette,
            text = "${(settings.vignette * 100).toInt()}%",
            onChange = onVignette
        )
        LabeledSlider(
            label = "颗粒噪点",
            value = settings.grain,
            text = "${(settings.grain * 100).toInt()}%",
            onChange = onGrain
        )
        LabeledSlider(
            label = "高斯模糊",
            value = settings.blurRadius / 25f,
            text = "${settings.blurRadius.toInt()} dp",
            onChange = { onBlur(it * 25f) }
        )
        SwitchRow(
            label = "冷调柔光",
            description = "在背景上叠加青蓝冷光渐变",
            checked = settings.coldLight,
            onCheckedChange = onColdLight
        )
    }
}

@Composable
fun LabeledSlider(
    label: String,
    value: Float,
    text: String,
    range: ClosedFloatingPointRange<Float> = 0f..1f,
    onChange: (Float) -> Unit
) {
    var local by remember(value) { mutableFloatStateOf(value) }
    Column(Modifier.padding(top = 12.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text(text = label, style = MaterialTheme.typography.bodySmall, color = TextMuted)
            Text(text = text, style = MaterialTheme.typography.labelSmall, color = Cyan)
        }
        Slider(
            value = local.coerceIn(range.start, range.endInclusive),
            onValueChange = {
                local = it
                onChange(it)
            },
            valueRange = range,
            colors = SliderDefaults.colors(
                thumbColor = Cyan,
                activeTrackColor = Cyan.copy(alpha = 0.8f),
                inactiveTrackColor = Color(0xFF1A2636)
            )
        )
    }
}

@Composable
fun SwitchRow(
    label: String,
    description: String? = null,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(Modifier.weight(1f)) {
            Text(text = label, style = MaterialTheme.typography.bodyMedium)
            if (description != null) {
                Text(
                    text = description,
                    style = MaterialTheme.typography.labelSmall,
                    color = TextMuted
                )
            }
        }
        Switch(
            checked = checked,
            onCheckedChange = onCheckedChange,
            colors = androidx.compose.material3.SwitchDefaults.colors(
                checkedThumbColor = Color(0xFF04121A),
                checkedTrackColor = Cyan
            )
        )
    }
}

@Composable
private fun PanelButton(
    text: String,
    icon: @Composable (() -> Unit)? = null,
    modifier: Modifier = Modifier,
    onClick: () -> Unit
) {
    Row(
        modifier = modifier
            .clip(RoundedCornerShape(14.dp))
            .background(Color(0xFF13202F))
            .clickable { onClick() }
            .padding(vertical = 12.dp),
        horizontalArrangement = Arrangement.Center,
        verticalAlignment = Alignment.CenterVertically
    ) {
        if (icon != null) icon()
        Text(
            text = text,
            style = MaterialTheme.typography.labelSmall,
            color = Color(0xFFBFD6FF),
            modifier = Modifier.padding(horizontal = 10.dp)
        )
    }
}
