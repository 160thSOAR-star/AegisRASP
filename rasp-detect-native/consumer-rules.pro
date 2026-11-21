# RASP native 接口不混淆：JNI 通过显式 RegisterNatives 注册，名字无需保留，
# 但 SDK 对外 API 需要稳定签名供宿主应用调用。
-keep class com.rasp.detect.RaspNative { *; }
-keep class com.rasp.detect.** { *; }
-keepclassmembers class com.rasp.detect.** { *; }
