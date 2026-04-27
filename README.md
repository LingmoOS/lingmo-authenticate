# Deepin Authentication

## 调试

### 假的指纹设备

用于在没有指纹设备时，方便使用虚拟指纹设备来测试。

代码实现在 [fake_device.go](./service/fingerprint/fake_device.go)，如果要启用这个功能，需要在 go build 编译选项中增加

```
-ldflags "-X pkg.deepin.io/dde/authentication/service/fingerprint.FakeDeviceEnabled=1"
```

### 假的密码认证

用于排除 PAM 模块影响测试密码验证功能。

代码实现在 [password_tx.go](./service/authenticate/password_tx.go)，如果要启用这个功能，需要在 go build 编译选项中增加

```
-ldflags "-X pkg.deepin.io/dde/authentication/service/authenticate.FakePasswordTxEnabled=1"
```

## 文档

- [deepin authentication](./docs/deepin_authenticate.org)
- [deepin fingerprint](./docs/deepin_fingerprint.org)
