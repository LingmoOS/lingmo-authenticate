## FAQ

### deepin_pam_unix、pam-modules、black_list 文件的作用

deepin_pam_unix: 该文件为PAM认证配置，pam-auth-update脚本会将PAM配置写入该文件。DA框架会使用该配置开启认证，以兼容传统PAM框架。
black_list: 配合DA框架的pam-auth-update脚本，在更新PAM配置时，会将black_list中的模块屏蔽。
pam-modules: 配合DA框架的pam-auth-update脚本，common-auth会被写成固定使用pam-modules中的认证配置。
