package com.rasp.detect.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

// 深色高级安全仪表盘配色：冷蓝 / 青灰 / 警示红
val DeepNight = Color(0xFF05080F)
val PanelDeep = Color(0xFF0B121C)
val Panel = Color(0xFF0E1622)
val ColdBlue = Color(0xFF4C8DFF)
val Cyan = Color(0xFF35D6C8)
val Amber = Color(0xFFF5B83D)
val WarnRed = Color(0xFFFF5A5A)
val SafeGreen = Color(0xFF31D0AA)
val TextPrimary = Color(0xFFDCE7F3)
val TextMuted = Color(0xFF8095AB)
val Hairline = Color(0xFF243244)

private val AegisScheme = darkColorScheme(
    primary = ColdBlue,
    onPrimary = Color.White,
    primaryContainer = Color(0xFF16253C),
    onPrimaryContainer = Color(0xFFBFD6FF),
    secondary = Cyan,
    onSecondary = Color(0xFF04121A),
    secondaryContainer = Color(0xFF0D2A2E),
    onSecondaryContainer = Color(0xFF9FF2E9),
    tertiary = Amber,
    onTertiary = Color(0xFF2A1D00),
    background = DeepNight,
    onBackground = TextPrimary,
    surface = Panel,
    onSurface = TextPrimary,
    surfaceVariant = Color(0xFF16202E),
    onSurfaceVariant = TextMuted,
    error = WarnRed,
    onError = Color.White,
    outline = Hairline,
    outlineVariant = Color(0xFF1A2634)
)

private val AegisTypography = Typography(
    displaySmall = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Bold,
        fontSize = 34.sp,
        letterSpacing = 0.sp
    ),
    headlineSmall = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 21.sp,
        letterSpacing = 0.2.sp
    ),
    titleMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 16.sp
    ),
    titleSmall = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Medium,
        fontSize = 14.sp
    ),
    bodyMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Normal,
        fontSize = 14.sp,
        lineHeight = 20.sp
    ),
    bodySmall = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Normal,
        fontSize = 12.sp,
        lineHeight = 17.sp
    ),
    labelSmall = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Medium,
        fontSize = 11.sp,
        letterSpacing = 0.4.sp
    )
)

@Composable
fun AegisTheme(accentIndex: Int = 0, content: @Composable () -> Unit) {
    val accent = when (accentIndex) {
        1 -> Cyan
        2 -> WarnRed
        else -> ColdBlue
    }
    MaterialTheme(
        colorScheme = AegisScheme.copy(primary = accent),
        typography = AegisTypography,
        content = content
    )
}

/** 证据等级对应的强调色。 */
fun gradeColor(key: String): Color = when (key) {
    "strong" -> WarnRed
    "indirect" -> Amber
    else -> Color(0xFF9AA9B8)
}

/** 风险等级对应的强调色。 */
fun riskColor(level: String): Color = when (level) {
    "high" -> WarnRed
    "suspicious" -> Amber
    else -> SafeGreen
}
