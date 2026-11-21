package com.rasp.detect

/**
 * Native 核心的唯一入口（JNI 层 rasp_jni.c 通过 RegisterNatives 注册对应方法）。
 *
 * 约定：
 *  - [runDetect] 会阻塞直到全部检测完成，必须在线程池中调用（RaspEngine 已保证）；
 *  - 检测过程中的每条证据通过 [EvidenceSink.onEvidence] 以单行 JSON 流式回调；
 *  - [submitEvidence] 用于把 Java 层才能拿到的证据（包列表多路径校验）并入同一聚合模型。
 */
object RaspNative {

    /** 证据流式回调：每次回调携带一条证据的 JSON。 */
    fun interface EvidenceSink {
        fun onEvidence(json: String)
    }

    private val loaded: Boolean = try {
        System.loadLibrary("aegisrasp")
        true
    } catch (t: Throwable) {
        false
    }

    fun isAvailable(): Boolean = loaded

    /**
     * 执行检测。
     * @param configJson 配置 JSON（fastMode / sandbox / whitelist / disabled）
     * @param whitelistJson 白名单 JSON（mounts / processes / properties / kernel / oem）
     * @param weightSpec 自定义权重 "ID=权重;ID=权重"
     * @param sink 证据流式回调，可为 null
     * @return 完整报告 JSON
     */
    external fun runDetect(
        configJson: String,
        whitelistJson: String,
        weightSpec: String,
        sink: EvidenceSink?
    ): String

    /** 提交 Java 层补充证据（必须在 runDetect 之前调用）。 */
    external fun submitEvidence(json: String)

    /** 请求中断当前检测（各检测项在超时/取消检查点退出）。 */
    external fun cancelDetect()

    /** native 版本信息，用于自检与报告头。 */
    external fun nativeVersion(): String

    /** 直接读系统属性区（绕过 Java 层 SystemProperties），用于 ZYS-008 双路径比对。 */
    external fun readProperty(key: String): String

    fun versionOrNull(): String? = if (loaded) runCatching { nativeVersion() }.getOrNull() else null
}
