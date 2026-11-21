package com.rasp.detect

/** 检测项静态元数据（ID / 名称 / 类别 / 等级 / 开销），供设置页开关与权重配置使用。 */
data class CheckMeta(
    val id: String,
    val name: String,
    val category: String,
    val grade: EvidenceGrade,
    val cost: String
)

object CheckCatalog {

    val entries: List<CheckMeta> = listOf(
        // 1. Mount Namespace & 文件视图隔离
        CheckMeta("MNT-001", "挂载视图自洽性校验（statx mnt_id vs mountinfo）", "mount", EvidenceGrade.STRONG, "低"),
        CheckMeta("MNT-002", "跨进程 mountinfo 结构比对（pidfd → init/system_server）", "mount", EvidenceGrade.STRONG, "中"),
        CheckMeta("MNT-003", "同路径文件 stat 元信息跨视图比对", "mount", EvidenceGrade.STRONG, "低"),
        CheckMeta("MNT-004", "匿名 overlay / tmpfs 覆盖系统分区痕迹", "mount", EvidenceGrade.STRONG, "低"),
        CheckMeta("MNT-005", "挂载点 propagation 属性异常", "mount", EvidenceGrade.INDIRECT, "低"),
        CheckMeta("MNT-006", "多路径读取一致性（mountinfo/mounts/raw+libc）", "mount", EvidenceGrade.INDIRECT, "低"),
        CheckMeta("MNT-008", "挂载只读标志与 statfs 一致性", "mount", EvidenceGrade.INDIRECT, "低"),
        CheckMeta("MNT-009", "挂载设备号与 statx 设备号一致性", "mount", EvidenceGrade.INDIRECT, "低"),
        CheckMeta("MNT-007", "沙箱子进程视图一致性", "sandbox", EvidenceGrade.STRONG, "中"),

        // 2. KernelSU 本体与进程痕迹
        CheckMeta("KSU-001", "ksud 守护进程间接特征（cmdline/comm 特征匹配）", "ksu", EvidenceGrade.STRONG, "中"),
        CheckMeta("KSU-002", "进程组与会话 ID 异常", "ksu", EvidenceGrade.INDIRECT, "低"),
        CheckMeta("KSU-003", "父进程链异常溯源", "ksu", EvidenceGrade.INDIRECT, "低"),
        CheckMeta("KSU-004", "memfd 无文件进程检测", "ksu", EvidenceGrade.STRONG, "中"),
        CheckMeta("KSU-005", "进程 fd 列表异常匿名文件检测", "ksu", EvidenceGrade.INDIRECT, "低"),

        // 3. 内核态间接痕迹
        CheckMeta("KRN-001", "系统调用耗时分布统计", "kernel", EvidenceGrade.INDIRECT, "中"),
        CheckMeta("KRN-002", "内核配置与版本指纹偏离", "kernel", EvidenceGrade.WEAK, "低"),
        CheckMeta("KRN-003", "task_struct 与 /proc 视图不一致", "kernel", EvidenceGrade.INDIRECT, "低"),
        CheckMeta("KRN-004", "cred 结构间接行为特征", "kernel", EvidenceGrade.STRONG, "低"),
        CheckMeta("KRN-005", "内核符号表异常间接推断", "kernel", EvidenceGrade.WEAK, "低"),
        CheckMeta("KRN-006", "内核时序自洽性（btime / uptime / BOOTTIME）", "kernel", EvidenceGrade.INDIRECT, "低"),
        CheckMeta("KRN-007", "syscall 返回码语义异常探针", "kernel", EvidenceGrade.INDIRECT, "低"),

        // 4. BPF 篡改痕迹
        CheckMeta("BPF-001", "anon_inode 异常数量统计", "bpf", EvidenceGrade.INDIRECT, "低"),
        CheckMeta("BPF-002", "进程 fd 中 bpf 类型匿名文件识别", "bpf", EvidenceGrade.STRONG, "中"),
        CheckMeta("BPF-003", "网络包处理时延异常统计", "bpf", EvidenceGrade.WEAK, "中"),
        CheckMeta("BPF-004", "cgroup 视图跨进程比对", "bpf", EvidenceGrade.INDIRECT, "低"),

        // 5. Zygisk / Shamiko / LSPosed / HMA
        CheckMeta("ZYS-001", "Zygote 注入间接痕迹检测", "zygisk", EvidenceGrade.INDIRECT, "中"),
        CheckMeta("ZYS-002", "Zygisk native bridge 异常检测", "zygisk", EvidenceGrade.INDIRECT, "低"),
        CheckMeta("ZYS-003", "Shamiko 挂载隔离特征", "zygisk", EvidenceGrade.STRONG, "中"),
        CheckMeta("ZYS-004", "LSPosed 方法 Hook 间接特征", "zygisk", EvidenceGrade.STRONG, "中"),
        CheckMeta("ZYS-005", "多路径应用包列表查询交叉校验", "zygisk", EvidenceGrade.INDIRECT, "中"),
        CheckMeta("ZYS-006", "Binder 调用结果一致性校验", "zygisk", EvidenceGrade.INDIRECT, "中"),
        CheckMeta("ZYS-007", "异常线程名与线程注入痕迹", "zygisk", EvidenceGrade.WEAK, "低"),
        CheckMeta("ZYS-008", "系统属性 Java/native 双路径一致性", "zygisk", EvidenceGrade.INDIRECT, "低"),

        // 6. Ptrace / 内存映射 / 注入
        CheckMeta("INJ-001", "进程内存映射异常匿名段检测", "inject", EvidenceGrade.INDIRECT, "低"),
        CheckMeta("INJ-002", "ptrace 后门痕迹间接检测", "inject", EvidenceGrade.STRONG, "低"),
        CheckMeta("INJ-003", "系统库函数入口完整性校验", "inject", EvidenceGrade.STRONG, "中"),
        CheckMeta("INJ-004", "Dex 文件匿名内存加载检测", "inject", EvidenceGrade.INDIRECT, "低"),
        CheckMeta("INJ-005", "非系统代码映射来源检测", "inject", EvidenceGrade.INDIRECT, "低"),

        // 7. SELinux & AVB & 系统完整性
        CheckMeta("SEL-001", "SELinux 域上下文异常检测", "selinux", EvidenceGrade.INDIRECT, "低"),
        CheckMeta("SEL-002", "SELinux 策略偏离度检测", "selinux", EvidenceGrade.WEAK, "低"),
        CheckMeta("SEL-003", "AVB2.0 校验状态检测", "selinux", EvidenceGrade.WEAK, "低"),
        CheckMeta("SEL-004", "系统分区完整性间接校验", "selinux", EvidenceGrade.INDIRECT, "低"),
        CheckMeta("SEL-005", "系统属性异常特征（属性区 vs build.prop）", "selinux", EvidenceGrade.INDIRECT, "低"),

        // 8. 反 Hook 自校验
        CheckMeta("AHK-001", "libc 关键函数入口完整性校验", "antihook", EvidenceGrade.STRONG, "低"),
        CheckMeta("AHK-002", "直调 syscall 与 libc 调用结果一致性校验", "antihook", EvidenceGrade.STRONG, "低"),
        CheckMeta("AHK-003", "检测代码段内存完整性校验", "antihook", EvidenceGrade.STRONG, "低"),
        CheckMeta("AHK-004", "JNI 函数表完整性校验", "antihook", EvidenceGrade.STRONG, "低"),
        CheckMeta("AHK-005", "函数地址与可执行段一致性", "antihook", EvidenceGrade.STRONG, "低"),
        CheckMeta("AHK-006", "openat2 与 openat 双路径一致性", "antihook", EvidenceGrade.STRONG, "中"),

        // 9. 文件系统视图一致性（1.0.1 新增）
        CheckMeta("FOPS-001", "目录枚举与直接访问不一致（procfs 目录过滤）", "fops", EvidenceGrade.STRONG, "低"),

        // 沙箱独立性
        CheckMeta("SBX-001", "clone3 沙箱独立性校验", "sandbox", EvidenceGrade.INDIRECT, "中")
    )

    val total: Int get() = entries.size

    fun byId(id: String): CheckMeta? = entries.firstOrNull { it.id == id }
}
