package com.rasp.detect

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** 报告导出：JSON / Markdown / HTML 三种格式，内容全部来自检测报告本身。 */
object ReportExporter {

    fun toJson(report: RaspReport): String = report.toJson().toString(2)

    fun toMarkdown(report: RaspReport): String {
        val sb = StringBuilder()
        val time = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())
            .format(Date(report.finishedAt))

        sb.appendLine("# Aegis RASP 运行时检测报告")
        sb.appendLine()
        sb.appendLine("| 项目 | 值 |")
        sb.appendLine("| --- | --- |")
        sb.appendLine("| 风险得分 | **${report.score} / 100** |")
        sb.appendLine("| 风险等级 | ${report.level.label}（${report.level.key}） |")
        sb.appendLine(String.format(Locale.US, "| 综合置信度 | %.0f%% |", report.confidence * 100))
        sb.appendLine("| 检测耗时 | ${report.durationMs} ms |")
        sb.appendLine("| 完成时间 | $time |")
        sb.appendLine("| 证据统计 | 强 ${report.counts.strong} / 间接 ${report.counts.indirect} / 弱 ${report.counts.weak} |")
        sb.appendLine("| 可执行项 | ${report.counts.available} / ${report.counts.total} |")
        sb.appendLine("| 反 Hook 自校验 | ${if (report.antiHookHit) "命中（疑似检测逻辑被篡改）" else "未命中"} |")
        sb.appendLine("| 设备 | ${report.device.model} · Android ${report.device.release} (API ${report.device.sdk}) · ${report.device.abi} |")
        sb.appendLine("| Build Tags | ${report.device.buildTags} |")
        sb.appendLine()

        sb.appendLine("## 命中证据")
        sb.appendLine()
        val hits = report.items.filter { it.hit }
        if (hits.isEmpty()) {
            sb.appendLine("未命中任何异常证据。")
        } else {
            sb.appendLine("| ID | 检测项 | 等级 | 置信度 | 说明 |")
            sb.appendLine("| --- | --- | --- | --- | --- |")
            hits.forEach { e ->
                val conf = String.format(Locale.US, "%.0f%%", e.confidence * 100)
                val note = e.error.ifBlank { e.rawText.take(120).replace("|", "\\|") }
                sb.appendLine("| ${e.id} | ${e.name} | ${e.grade.label} | $conf | $note |")
            }
        }
        sb.appendLine()

        sb.appendLine("## 全部检测项")
        sb.appendLine()
        report.items.forEach { e ->
            val status = when {
                !e.available -> "不可用"
                e.hit -> "命中"
                else -> "正常"
            }
            sb.appendLine("### ${e.id} · ${e.name}")
            sb.appendLine()
            sb.appendLine("- 类别：${categoryLabel(e.category)}")
            sb.appendLine("- 等级：${e.grade.label}（权重 ${e.grade.weight}）")
            sb.appendLine("- 状态：$status（置信度 ${String.format(Locale.US, "%.0f%%", e.confidence * 100)}）")
            if (e.error.isNotBlank()) sb.appendLine("- 错误/限制：${e.error}")
            sb.appendLine()
            sb.appendLine("```json")
            sb.appendLine(e.rawPretty)
            sb.appendLine("```")
            sb.appendLine()
        }

        sb.appendLine("---")
        sb.appendLine("本报告由 Aegis RASP 本地生成，仅包含设备本地采集的痕迹证据，不含任何远程校验结果。")
        return sb.toString()
    }

    fun toHtml(report: RaspReport): String {
        val time = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())
            .format(Date(report.finishedAt))
        val color = when (report.level) {
            RiskLevel.SAFE -> "#31d0aa"
            RiskLevel.SUSPICIOUS -> "#f5b83d"
            RiskLevel.HIGH -> "#ff5a5a"
        }
        val sb = StringBuilder()
        sb.append(
            """
            <!DOCTYPE html>
            <html lang="zh-CN"><head><meta charset="utf-8"/>
            <meta name="viewport" content="width=device-width,initial-scale=1"/>
            <title>Aegis RASP 检测报告</title>
            <style>
            :root{color-scheme:dark}
            body{margin:0;padding:24px;background:#070b12;color:#dbe7f3;
                 font-family:-apple-system,"Segoe UI",Roboto,"Helvetica Neue",sans-serif}
            .wrap{max-width:900px;margin:0 auto}
            h1{font-size:22px;letter-spacing:.5px}
            .hero{display:flex;align-items:center;gap:24px;padding:22px;border-radius:22px;
                  background:linear-gradient(135deg,rgba(30,44,68,.9),rgba(12,18,30,.9));
                  border:1px solid rgba(120,180,255,.18)}
            .score{font-size:46px;font-weight:700;color:%COLOR%}
            .level{font-size:18px;color:%COLOR%}
            .meta{color:#7f93ab;font-size:13px;line-height:1.7}
            table{width:100%;border-collapse:collapse;margin:16px 0;font-size:13px}
            th,td{padding:8px 10px;border-bottom:1px solid rgba(120,180,255,.12);text-align:left}
            th{color:#8ea6c0;font-weight:600}
            .tag{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px}
            .strong{background:rgba(255,90,90,.16);color:#ff8080}
            .indirect{background:rgba(245,184,61,.16);color:#f5b83d}
            .weak{background:rgba(160,175,190,.16);color:#a9b7c6}
            details{margin:8px 0;border:1px solid rgba(120,180,255,.14);border-radius:14px;padding:10px 14px;
                    background:rgba(16,24,36,.65)}
            summary{cursor:pointer;font-weight:600}
            pre{white-space:pre-wrap;word-break:break-all;font-size:12px;color:#9fb4c9}
            footer{margin-top:24px;color:#5f7387;font-size:12px}
            </style></head><body><div class="wrap">
            <h1>Aegis RASP 运行时检测报告</h1>
            <div class="hero">
              <div><div class="score">%SCORE%</div><div class="meta">风险得分 / 100</div></div>
              <div style="flex:1">
                <div class="level">%LEVEL%</div>
                <div class="meta">%SUMMARY%</div>
                <div class="meta">置信度 %CONF% · 耗时 %DURATION% ms · %TIME%</div>
                <div class="meta">%DEVICE%</div>
              </div>
            </div>
            <table><thead><tr><th>ID</th><th>检测项</th><th>等级</th><th>置信度</th><th>状态</th></tr></thead><tbody>
            """.trimIndent()
                .replace("%COLOR%", color)
                .replace("%SCORE%", report.score.toString())
                .replace("%LEVEL%", report.level.label)
                .replace("%SUMMARY%", report.level.summary)
                .replace("%CONF%", String.format(Locale.US, "%.0f%%", report.confidence * 100))
                .replace("%DURATION%", report.durationMs.toString())
                .replace("%TIME%", time)
                .replace(
                    "%DEVICE%",
                    "${report.device.model} · Android ${report.device.release} (API ${report.device.sdk}) · ${report.device.abi}"
                )
        )
        report.sortedItems().forEach { e ->
            val status = when {
                !e.available -> "不可用"
                e.hit -> "命中"
                else -> "正常"
            }
            sb.append(
                "<tr><td>${e.id}</td><td>${e.name}</td>" +
                    "<td><span class=\"tag ${e.grade.key}\">${e.grade.label}</span></td>" +
                    "<td>${String.format(Locale.US, "%.0f%%", e.confidence * 100)}</td><td>$status</td></tr>\n"
            )
        }
        sb.append("</tbody></table>\n")
        report.items.forEach { e ->
            sb.append("<details><summary>${e.id} · ${e.name}</summary>")
            sb.append("<pre>${escape(e.rawPretty)}</pre>")
            if (e.error.isNotBlank()) sb.append("<pre>限制/错误：${escape(e.error)}</pre>")
            sb.append("</details>\n")
        }
        sb.append("<footer>本报告由 Aegis RASP 本地生成，不含任何远程校验结果。</footer></div></body></html>")
        return sb.toString()
    }

    fun categoryLabel(category: String): String = when (category) {
        "mount" -> "挂载与文件视图隔离"
        "ksu" -> "KernelSU 本体与进程痕迹"
        "kernel" -> "内核态间接痕迹"
        "bpf" -> "BPF 篡改痕迹"
        "zygisk" -> "Zygisk / Shamiko / LSPosed / HMA"
        "inject" -> "注入与内存映射"
        "selinux" -> "SELinux / AVB / 系统完整性"
        "antihook" -> "反 Hook 自校验"
        "sandbox" -> "沙箱与跨视图校验"
        "fops" -> "文件系统视图一致性"
        else -> "其他"
    }

    private fun escape(s: String): String = s
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
}
