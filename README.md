# Pico All

面向 Waveshare RP2350-One 的 FIDO2/U2F、OpenPGP/PIV 与 SmartCard-HSM 组合固件

当前已通过固件编译与主机端存储、应用切换测试；尚未完成板上协议验证

## 构建

已验证 Pico SDK 2.3.1、Arm GNU Toolchain 15.2、CMake 3.31 与 Ninja

```sh
cmake -S . -B build -G Ninja -DPICO_SDK_PATH=/path/to/pico-sdk
cmake --build build
```

默认板型为 `waveshare_rp2350_one`；构建会获取固定版本的密码库依赖，输出 `build/pico_all.uf2`

本地签名使用独立输出文件；私钥放在被 Git 忽略的 `.private/` 中

```sh
picotool seal --sign build/pico_all.uf2 build/pico_all_signed.uf2 .private/private_key.pem
picotool info -a build/pico_all_signed.uf2
```

## 验证

Linux 主机上可运行存储与应用切换回归测试

```sh
cmake -S tests -B build/tests
cmake --build build/tests
ctest --test-dir build/tests --output-on-failure
```

## 刷写前

- 本固件采用独立的应用存储格式；不迁移旧固件中的凭据，非空旧存储会拒绝加载
- 上游首次启动可能生成硬件密钥，并写入、锁定 OTP 区域；清理旧数据和永久硬件初始化应在确认后进行
- 固件签名不会自动启用 Secure Boot；Secure Boot 与锁定需要单独配置
- 默认 USB ID 为开发用途的 `FEFF:FCFD`；客户端及驱动适配仍需板上验证

源码来自 [Pico FIDO](https://github.com/polhenarejos/pico-fido)、[Pico OpenPGP](https://github.com/polhenarejos/pico-openpgp)、[Pico HSM](https://github.com/polhenarejos/pico-hsm) 与 [Pico Keys SDK](https://github.com/polhenarejos/pico-keys-sdk)；精确版本见 `upstream.json`，许可证见 `LICENSE`
