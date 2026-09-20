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

Windows 上已完成以下板上协议验证；这些结果不代表真实客户端兼容性测试已完成

- FIDO2：驻留凭据注册/认证与验签、PIN、凭据枚举、实体按键确认、等待超时，以及取消后立即连续查询
- U2F：正常 PIN 解锁后的注册证明验签、认证验签、实体按键与签名计数器；设置 FIDO PIN 后，当前固件的 U2F 使用依赖先解锁 PIN 会话
- OpenPGP：P-256 签名与 ECDH、RSA-2048 认证签名与通过 MSE 选钥的解密，以及原签名密钥保留
- PIV：P-256 签名与 ECDH、RSA-2048 签名/私钥解密、生成证书读取，以及 OpenPGP 数据保留
- HSM：P-256 签名与 ECDH、RSA-2048 PKCS#1 v1.5/PSS 签名和 PKCS#1 v1.5/OAEP 解密、AES-256 CBC 往返、CMAC 重复性与消息差异、按键确认与超时拒绝
- 管理接口：按键确认后允许原样配置写入，不确认时超时拒绝；重启和更新固件后的数据保存已验证

实际拔插断电后，灯光配置、安全状态、OpenPGP/PIV 公钥、HSM 密钥与选项、FIDO PIN 与既有凭据均通过恢复检查；HSM 重置后，FIDO、OpenPGP、PIV 与共享配置保持原样；其他应用重置的实机覆盖仍待补充；设置 PIN 后纯 U2F 客户端的冷启动使用方式尚待确认；RSA-2048 卡内生成可能耗时数分钟，一次 OpenPGP 实测约 162 秒

管理接口中要求实体确认的操作，以及启用按键选项的 HSM 操作，使用已配置的等待时长；未配置时默认等待 30 秒

智能卡长响应续传统一按 USB 接口编号路由，避免与 FIDO HID 的驱动局部编号重叠；已验证读取 PIV 长证书后可连接 FIDO 并读取既有凭据

Linux 主机上可运行存储、应用切换、APDU 续传路由与 LED 状态时序回归测试

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
| 蓝色常亮 | 已确认进入固件更新模式；不表示刷写进度或成功 |
| 黄色闪烁，亮灭各 300 毫秒 | 等待按下 BOOT/BOOTSEL 确认 |
| 绿色短闪 | 按键确认或应用完成提示 |
| 红色两闪 | 按键确认超时 |
| 紫色每 2 秒短闪 | USB 尚未就绪或已断开 |
| 熄灭 | USB 挂起或灯光关闭 |

普通请求保持绿色呼吸且不重置周期；按键提示与更新模式优先于完成提示；蓝灯在固件请求进入 BOOTSEL 前设置，进入 ROM 后由启动程序接管，断电后灯光不保留；已在 RP2350-One 实物确认进入 BOOTSEL 后蓝灯常亮，并验证可返回应用

## 刷写前

- 本固件采用独立的应用存储格式；不迁移旧固件中的凭据，非空旧存储会拒绝加载
- 当前开发固件使用无硬件 OTP 模式；启动不写入、迁移密钥或设置页面权限，管理命令也不支持启用 Secure Boot / Secure Lock
- 无 OTP 后备路径缺少硬件随机根密钥的保护；先用于开发测试，后续启用硬件密钥时需处理数据迁移或重新初始化
- 不可逆的 OTP 初始化留到开发测试完成后实现；Secure Boot 与 Secure Lock 留待 Pico Forge 专项维护，固件签名本身不会启用这些功能
- 默认 USB ID 为开发用途的 `FEFF:FCFD`；Windows FIDO 与 CCID 枚举已验证，真实应用兼容性仍需继续测试

源码来自 [Pico FIDO](https://github.com/polhenarejos/pico-fido)、[Pico OpenPGP](https://github.com/polhenarejos/pico-openpgp)、[Pico HSM](https://github.com/polhenarejos/pico-hsm) 与 [Pico Keys SDK](https://github.com/polhenarejos/pico-keys-sdk)；精确版本见 `upstream.json`，许可证见 `LICENSE`
