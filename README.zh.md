# Pico All

[English](README.md) | 中文

面向 Waveshare RP2350-One 的 FIDO2/U2F、OpenPGP/PIV、SmartCard-HSM 三合一固件

当前为开发版本，未启用硬件 OTP 初始化与 Secure Boot / Secure Lock；暂勿用于重要凭据

## 构建

需要 Arm 工具链、Pico SDK 2.3.1、CMake 3.31+ 和 Ninja

```sh
cmake -S . -B build -G Ninja -DPICO_SDK_PATH=/path/to/pico-sdk
cmake --build build
```

进入 BOOTSEL 模式，将 `build/pico_all.uf2` 复制到开发板的 USB 磁盘；不迁移上游固件中的既有凭据

## 使用

绿灯呼吸：待机 · 黄灯闪烁：按 BOOTSEL 确认 · 蓝灯：固件更新模式 · 红灯闪烁：确认超时

设置 FIDO PIN 后，当前 U2F 使用需要先解锁 PIN 会话

## 许可证

[AGPL-3.0](LICENSE) · 基于 Pico FIDO、Pico OpenPGP、Pico HSM 与 Pico Keys SDK；作者和引用版本见 [upstream.json](upstream.json)
