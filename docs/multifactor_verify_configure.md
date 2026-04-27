
# 多因子认证应用配置

配置采用json配置方式，配置内容如下：

```json
{
    "ApplicationType" : "login",
    "RequestVerificationType" : [
        {
            "Type": "password",
            "Service": ""
        },
        {
            "Type": "fingerprint",
            "Service": ""
        }
    ],
}
```

各参数说明：

- ApplicationType : （string）应用程序认证类型
    **ApplicationType 指定应用程序的认证类型，对于同种认证类型采取同样的认证方式**
    可以使用的 ApplicationType 有以下值:

    ```c
    {
        login,          // 登录类型的程序
        lock,           // 锁屏类型的程序
        authorization,          // 提权类型的程序
        other,          // 其他
        * ,             // 所有类型
    }
    ```

- RequestVerificationType : （[]）要求必须验证且需要通过的验证方式
  该字段为一个列表，可配置多个子字段。

  各字段含义:

  - Type: 认证方式，配置了即需要开启。该字段需填写 int 类型数据

    可以为以下值

    ```c
    enum {
            password,           // 启用密码认证
            fingerprint,        // 启用指纹认证
            face,               // 启用人脸认证
            ad,                 // 启用 AD 域认证
            ukey,               // 启用 UKey 认证
        }
    ```
  - Service: 指定该种认证方式对应的 DBus 服务名，**如果不指定或者服务名为 "*" ，则为使用默认的服务**

# 配置文件命名规则
配置文件命名规则为 `mfa-{appType}-{priority}.json`，
其中：
  - `appType` 为应用程序类型，对应上述 `applicationType` 字段的值
  - `priority` 为该配置文件的优先级，推荐 0-99,其中 0 的优先级最低，99 的优先级最高。不同应用之间的优先级是不互相干扰的。其中所有应用的优先级最低，当存在所有应用的优先级与单个应用的优先级时，将使用单个应用的配置。例如配置了针对所有应用的配置 `mfa-all-01.json`, 同时也提供了 `mfa-login-01.json`, 那么登录 类型的应用将仍然使用 `mfa-login-01.json` 的配置，而其他应用则采用 `mfa-all-01.json` 的配置。
例如：
  - 登录程序的多因配置为: `mfa-login-01.json`
  - 所有程序的多因配置为: `mfa-all-01.json`
# 配置文件存放路径
存放路径为 `/usr/share/deepin-authentication/mfa-conf.d/`
