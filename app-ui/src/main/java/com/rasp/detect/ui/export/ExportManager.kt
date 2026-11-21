package com.rasp.detect.ui.export

import android.content.ClipData
import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.core.content.FileProvider
import com.rasp.detect.RaspReport
import com.rasp.detect.ReportExporter
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** 报告导出：写入缓存目录后通过 FileProvider 分享，不申请存储权限。 */
class ExportManager(private val context: Context) {

    enum class Format(val extension: String, val mime: String) {
        JSON("json", "application/json"),
        MARKDOWN("md", "text/markdown"),
        HTML("html", "text/html")
    }

    private fun exportDir(): File =
        File(context.cacheDir, "exports").apply { if (!exists()) mkdirs() }

    fun writeReport(report: RaspReport, format: Format): Uri {
        val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
        val file = File(exportDir(), "aegis-rasp-$stamp.${format.extension}")
        val content = when (format) {
            Format.JSON -> ReportExporter.toJson(report)
            Format.MARKDOWN -> ReportExporter.toMarkdown(report)
            Format.HTML -> ReportExporter.toHtml(report)
        }
        file.writeText(content)
        return FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
    }

    fun share(uri: Uri, mime: String, subject: String) {
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = mime
            putExtra(Intent.EXTRA_STREAM, uri)
            putExtra(Intent.EXTRA_SUBJECT, subject)
            putExtra(Intent.EXTRA_TEXT, "Aegis RASP 本地检测报告（不含任何远程校验数据）")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            clipData = ClipData.newRawUri("report", uri)
        }
        context.startActivity(Intent.createChooser(intent, "分享检测报告").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }

    fun openHtml(uri: Uri) {
        val intent = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, "text/html")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        runCatching { context.startActivity(intent) }
    }

    fun clearCache(): Int {
        val dir = exportDir()
        val files = dir.listFiles() ?: return 0
        var removed = 0
        files.forEach { if (it.delete()) removed++ }
        return removed
    }

    fun copyToClipboard(label: String, text: String) {
        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText(label, text))
    }
}
