package com.rasp.detect

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Process
import org.json.JSONObject

/**
 * Java 层补充探针。
 *
 * 多路径包列表校验（ZYS-005）与 Binder 一致性校验（ZYS-006）必须调用 PackageManager / binder，
 * native 层没有对应合法接口，因此在这里执行后通过 [RaspNative.submitEvidence] 回注同一套
 * 证据聚合与加权打分模型（架构上仍保持「Native 为核心、Java 只做接口与转发」）。
 */
class JavaProbes(private val context: Context) {

    fun run(): List<Evidence> =
        listOfNotNull(packageMultiPath(), binderConsistency(), propertyCrossCheck())

    private fun now(): Long = System.currentTimeMillis()

    private fun unavailable(id: String, name: String, category: String, grade: EvidenceGrade, err: String): Evidence =
        Evidence(
            id = id, name = name, category = category, grade = grade,
            confidence = 0.0, hit = false, available = false,
            rawText = JSONObject().put("status", "unavailable").toString(),
            error = err, timestamp = now()
        )

    /** 三条独立查询路径交叉校验，对抗 HideMyApplist Next 的包列表隐藏。 */
    private fun packageMultiPath(): Evidence {
        val pm = context.packageManager
        val installed = runCatching { pm.getInstalledPackages(0).map { it.packageName }.toSet() }
            .getOrElse { return unavailable("ZYS-005", "多路径应用包列表查询交叉校验", "zygisk", EvidenceGrade.INDIRECT, it.message ?: "getInstalledPackages failed") }
        val apps = runCatching { pm.getInstalledApplications(0).map { it.packageName }.toSet() }
            .getOrDefault(emptySet())
        val uidPkgs = runCatching { pm.getPackagesForUid(Process.myUid())?.toSet() ?: emptySet() }
            .getOrDefault(emptySet())
        val launcher = runCatching {
            val intent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
            pm.queryIntentActivities(intent, 0).map { it.activityInfo.packageName }.toSet()
        }.getOrDefault(emptySet())

        // 启动器可见但 PackageManager 主体列表不可见 => 包列表被过滤
        val hiddenFromInstalled = launcher - installed
        // Applications 列表与 Packages 列表不一致 => 其中一条路径被 Hook
        val appsMissing = installed - apps
        val appsExtra = apps - installed

        val hit = hiddenFromInstalled.isNotEmpty() || appsMissing.isNotEmpty() || appsExtra.isNotEmpty()
        val raw = JSONObject().apply {
            put("installedCount", installed.size)
            put("applicationsCount", apps.size)
            put("launcherCount", launcher.size)
            put("uidPackages", uidPkgs.size)
            put("hiddenFromInstalled", hiddenFromInstalled.take(20).joinToString(","))
            put("appsMissing", appsMissing.take(20).joinToString(","))
            put("appsExtra", appsExtra.take(20).joinToString(","))
        }
        return Evidence(
            id = "ZYS-005", name = "多路径应用包列表查询交叉校验", category = "zygisk",
            grade = EvidenceGrade.INDIRECT,
            confidence = if (hit) 0.65 else 0.0,
            hit = hit, available = true, rawText = raw.toString(), error = "", timestamp = now()
        )
    }

    /**
     * Binder 原始结果与 Java 封装结果一致性校验。
     * android.os.ServiceManager / IPackageManager 属于非 SDK 接口，第三方应用可能因隐藏 API
     * 限制而不可用；不可用时明确标记为 unavailable，绝不伪造结论。
     */
    private fun binderConsistency(): Evidence {
        val binderResult = runCatching { queryPackagesViaBinder() }.getOrNull()
        val facade = runCatching {
            context.packageManager.getInstalledPackages(0).map { it.packageName }.toSet()
        }.getOrElse {
            return unavailable("ZYS-006", "Binder 调用结果一致性校验", "zygisk", EvidenceGrade.INDIRECT, it.message ?: "facade failed")
        }
        if (binderResult == null) {
            return unavailable("ZYS-006", "Binder 调用结果一致性校验", "zygisk", EvidenceGrade.INDIRECT, "binder direct query blocked by hidden API policy")
        }

        val onlyBinder = binderResult - facade
        val onlyFacade = facade - binderResult
        val hit = onlyBinder.isNotEmpty() || onlyFacade.isNotEmpty()
        val raw = JSONObject().apply {
            put("binderCount", binderResult.size)
            put("facadeCount", facade.size)
            put("onlyBinder", onlyBinder.take(20).joinToString(","))
            put("onlyFacade", onlyFacade.take(20).joinToString(","))
        }
        return Evidence(
            id = "ZYS-006", name = "Binder 调用结果一致性校验", category = "zygisk",
            grade = EvidenceGrade.INDIRECT,
            confidence = if (hit) 0.7 else 0.0,
            hit = hit, available = true, rawText = raw.toString(), error = "", timestamp = now()
        )
    }

    /**
     * ZYS-008：系统属性 Java/native 双路径一致性。
     *
     * `Build.MODEL` / `Build.FINGERPRINT` / `Build.VERSION.SDK_INT` 在进程启动早期由属性区快照而来，
     * 之后即使有模块 Hook 了 `SystemProperties.get()`（用于伪造指纹、隐藏 test-keys），
     * 这些 Java 静态字段也不会随之改变；而 native 直接读属性区拿到的是"当前值"。
     * 两者不一致 => 属性读取路径被拦截或属性区被改写。
     */
    private fun propertyCrossCheck(): Evidence {
        val pairs = listOf(
            Triple("ro.product.model", "Build.MODEL", android.os.Build.MODEL),
            Triple("ro.build.version.sdk", "SDK_INT", android.os.Build.VERSION.SDK_INT.toString()),
            Triple("ro.build.fingerprint", "Build.FINGERPRINT", android.os.Build.FINGERPRINT)
        )

        var checked = 0
        val diffs = ArrayList<String>()
        for ((prop, label, javaValue) in pairs) {
            val nativeValue = runCatching { RaspNative.readProperty(prop) }.getOrNull() ?: continue
            if (nativeValue.isEmpty()) continue
            checked++
            if (javaValue.isNotEmpty() && nativeValue != javaValue) {
                diffs += "$label(native=$nativeValue, java=$javaValue)"
            }
        }

        if (checked == 0) {
            return unavailable(
                "ZYS-008", "系统属性 Java/native 双路径一致性", "zygisk",
                EvidenceGrade.INDIRECT, "native readProperty unavailable"
            )
        }

        val hit = diffs.isNotEmpty()
        val raw = JSONObject().apply {
            put("checked", checked)
            put("mismatches", diffs.size)
            put("detail", diffs.joinToString("; "))
        }
        return Evidence(
            id = "ZYS-008", name = "系统属性 Java/native 双路径一致性", category = "zygisk",
            grade = EvidenceGrade.INDIRECT,
            confidence = if (hit) 0.6 else 0.0,
            hit = hit, available = true, rawText = raw.toString(), error = "", timestamp = now()
        )
    }

    /** 直接通过 package 服务的 binder 事务查询已安装包名，绕过 PackageManager 门面。 */
    private fun queryPackagesViaBinder(): Set<String> {
        val serviceManager = Class.forName("android.os.ServiceManager")
        val getService = serviceManager.getMethod("getService", String::class.java)
        val binder = getService.invoke(null, "package") as? android.os.IBinder ?: error("package service unavailable")
        val stub = Class.forName("android.content.pm.IPackageManager\$Stub")
        val asInterface = stub.getMethod("asInterface", android.os.IBinder::class.java)
        val pm = asInterface.invoke(null, binder) ?: error("asInterface returned null")
        val longType = Long::class.javaPrimitiveType ?: error("no long primitive")
        val intType = Int::class.javaPrimitiveType ?: error("no int primitive")
        val method = pm.javaClass.getMethod("getInstalledPackages", longType, intType)
        val userId = Process.myUid() / 100000
        val slice = method.invoke(pm, 0L, userId)
        val list = runCatching {
            slice.javaClass.getMethod("getList").invoke(slice) as List<*>
        }.getOrElse {
            @Suppress("UNCHECKED_CAST")
            slice as? List<*> ?: error("unexpected return type")
        }
        return list.mapNotNull { item ->
            runCatching {
                val name = item!!.javaClass.getMethod("getPackageName").invoke(item) as? String
                name
            }.getOrNull()
        }.toSet()
    }
}
