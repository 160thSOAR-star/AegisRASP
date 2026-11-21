# keystore 目录说明

这个目录**不存放任何私钥**，仓库里只有这份说明。

## 为什么目录是空的

签名私钥 `aegis-release.jks` 就是应用的"身份"：一旦泄露，别人可以用同一包名签出
冒充本应用的分发物；一旦丢失，已安装的设备将无法覆盖升级（只能卸载重装、丢数据）。
所以它只应存在于你的本地机器（以及密码管理器 / 加密磁盘里的备份），
**永远不进 Git 仓库**。`.gitignore` 已排除：

```
keystore/*.jks
keystore/keystore.properties
```

## 本地打包怎么配

1. 把私钥放到 `keystore/aegis-release.jks`（PKCS12 格式，别名为 `aegis`）。
2. 在同一目录创建 `keystore/keystore.properties`：

```properties
storeFile=keystore/aegis-release.jks
storePassword=<你的库口令>
keyAlias=aegis
keyPassword=<你的密钥口令>
```

3. 正常执行 `./gradlew :app-ui:assembleRelease`，`app-ui/build.gradle.kts` 会自动读取这份口令。

## 没有私钥能编译吗

可以。缺少 `keystore.properties` 或私钥时，构建不会中断：

- `debug` 退回默认调试签名；
- `release` 产物不签名（只有 `adb install` 会失败，编译和 R8 正常）。

Gradle 会打印一条 `[AegisRASP] 未找到 ...` 的警告，属预期行为。

## 想让别人验证"同一发布者"怎么办

用**证书指纹**而不是私钥来证明身份。每个 APK 里都带公钥证书，任何人都能验证：

```bash
apksigner verify --print-certs app-release.apk
```

本项目历史版本的证书 SHA-256 记录在 `docs/06-签名与迭代.md`，指纹一致即说明出自同一密钥。

## 重新生成密钥（仅在你确定放弃旧身份时）

```bash
keytool -genkeypair -v -keystore keystore/aegis-release.jks -alias aegis \
  -keyalg RSA -keysize 2048 -validity 10000 \
  -storepass <新库口令> -keypass <新密钥口令> \
  -dname "CN=Aegis RASP, OU=Security, O=Aegis, C=CN"
```

换密钥 = 换应用身份：老用户无法升级，只能卸载重装。
