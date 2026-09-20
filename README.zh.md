# Pico All

[English](README.md) | 中文

面向 Waveshare RP2350-One 的 FIDO2/U2F、OpenPGP/PIV、SmartCard-HSM 三合一固件

已在 RP2350-One（A2）实测 OTP 初始化、Secure Boot / Lock 和签名更新；A2 的[硬件安全勘误](https://www.raspberrypi.com/news/rp2350-a4-rp2354-and-a-new-hacking-challenge/)仍适用。

## 构建

需要 Arm 工具链、Pico SDK 2.3.1、CMake 3.31+ 和 Ninja

```sh
cmake -S . -B build -G Ninja -DPICO_SDK_PATH=/path/to/pico-sdk
cmake --build build
```

进入 BOOTSEL 模式，将 `build/pico_all.uf2` 复制到开发板的 USB 磁盘。已启用 Secure Boot 时，须先用已登记的密钥签名。不迁移上游固件中的既有凭据。

## 使用

绿灯呼吸：待机 · 黄灯闪烁：按 BOOTSEL 确认 · 蓝灯：固件更新模式 · 红灯闪烁：确认超时

新 U2F 凭据插入后按键即可使用，不依赖 FIDO2 PIN 解锁；旧 U2F 凭据仍需先解锁，重新注册即可使用新方式。

## 固件工具

需要 Python 3.10+，并将 [picotool](https://github.com/raspberrypi/picotool) 加入 PATH。一个脚本提供板内信息、本地签名、校验刷写和安全配置。命令会在需要时请求进入 BOOTSEL；黄灯闪烁后短按并松开按钮即可。清空准备和启动检查使用正常模式。

```sh
python -m pip install -r requirements.txt
python firmware.py -h
```

使用 `-h` 查看速查，`--help` 查看详情和示例，例如 `python firmware.py security enable --help`。固件路径统一作为位置参数：`python firmware.py security load-key signed.uf2 -s SERIAL`。

使用 `python firmware.py device bootsel` 进入更新模式，`python firmware.py device reboot` 返回正常固件，无需刷写或按 RESET。连接多块板子时加上 `-s SERIAL`。清空准备和启用之间不要重启正常固件。

安全配置顺序：**登记密钥 → 加固 → 清空准备 → 启用 → 启动检查 → 锁定**。各命令的 `--help` 会说明当前步骤；默认只预览，提供 `--apply` 后才进入确认。不可逆阶段之间需要彻底断电并测试。

签名启动和调试保护生效后，固件才会自动初始化 OTP 设备根。首次配置要求凭据区为空；清空准备会在板上按键确认后删除应用凭据、PIN 和设置。已有 OTP 根在更新后保留。最终锁定会关闭密钥轮换，务必离线备份签名密钥；仍可通过 BOOTSEL 更新签名固件。

## 许可证

[AGPL-3.0](LICENSE) · 基于 Pico FIDO、Pico OpenPGP、Pico HSM 与 Pico Keys SDK；作者和引用版本见 [upstream.json](upstream.json)
