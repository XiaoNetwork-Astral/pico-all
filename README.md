# Pico All

面向 Waveshare RP2350-One 的 FIDO2/U2F、OpenPGP/PIV 与 SmartCard-HSM 组合固件

当前已通过主机端存储、应用切换测试及 RP2350-One 首轮上板验证；完整客户端兼容性仍待验证

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

Windows 上已验证 USB 枚举、FIDO2 驻留凭据注册与认证、OpenPGP 和 HSM 的 P-256 密钥生成与签名，以及重启和更新固件后的密钥保存；FIDO 注册已验证实体按键确认；PIV 目前仅验证应用选择

Linux 主机上可运行存储、应用切换与 LED 状态时序回归测试

```sh
cmake -S tests -B build/tests
cmake --build build/tests
ctest --test-dir build/tests --output-on-failure
```

## 设备名称与灯光

USB 厂商名称和默认产品名称均为 `Pico All`；可用 CMake 参数 `-DPICO_ALL_MANUFACTURER="Your Name"` 与 `-DPICO_ALL_PRODUCT="Your Key"` 自定义，长度各不超过 31 字节

管理接口设置的设备自定义名称会同时用于 USB 产品名称与 HSM 默认标签；源码版权信息与上游出处保留

RP2350-One 的 RGB 灯使用 GPIO16、WS2812 驱动与 RGB 顺序（该板型默认值；显式配置优先）；物理亮度默认 1，配置范围为 0–15，旧配置中的超范围值按 15 处理

| 灯光 | 含义 |
| --- | --- |
| 低亮绿色呼吸，约 2 秒一轮（渐亮、渐暗各 1 秒） | USB 已就绪，待机 |
| 蓝色常亮 | 请求处理超过 150 毫秒 |
| 黄色闪烁，亮灭各 300 毫秒 | 等待按下 BOOT/BOOTSEL 确认 |
| 绿色短闪 | 按键确认或应用完成提示 |
| 红色两闪 | 按键确认超时 |
| 紫色每 2 秒短闪 | USB 尚未就绪或已断开 |
| 熄灭 | USB 挂起或灯光关闭 |

按键提示优先于完成提示；短暂主机轮询不显示蓝灯，也不重置呼吸周期，以减少无意义闪烁

## 刷写前

- 本固件采用独立的应用存储格式；不迁移旧固件中的凭据，非空旧存储会拒绝加载
- 当前开发固件使用无硬件 OTP 模式；启动不写入、迁移密钥或设置页面权限，管理命令也不支持启用 Secure Boot / Secure Lock
- 无 OTP 后备路径缺少硬件随机根密钥的保护；先用于开发测试，后续启用硬件密钥时需处理数据迁移或重新初始化
- 不可逆的 OTP 初始化留到开发测试完成后实现；Secure Boot 与 Secure Lock 留待 Pico Forge 专项维护，固件签名本身不会启用这些功能
- 默认 USB ID 为开发用途的 `FEFF:FCFD`；Windows FIDO 与 CCID 枚举已验证，真实应用兼容性仍需继续测试

源码来自 [Pico FIDO](https://github.com/polhenarejos/pico-fido)、[Pico OpenPGP](https://github.com/polhenarejos/pico-openpgp)、[Pico HSM](https://github.com/polhenarejos/pico-hsm) 与 [Pico Keys SDK](https://github.com/polhenarejos/pico-keys-sdk)；精确版本见 `upstream.json`，许可证见 `LICENSE`
