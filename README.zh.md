# Pico All

[English](README.md) | 中文

将 **Waveshare RP2350-One** 变成 USB 安全密钥，在同一固件中使用 FIDO2/U2F、OpenPGP/PIV、SmartCard-HSM 和 OATH/OTP

## 功能

- 通行密钥、智能卡密钥、动态口令和可编程 OTP 槽位
- 使用 [PicoForge All](https://github.com/XiaoNetwork-Astral/pico-forge-all) 管理设备
- 可选安全事件记录，支持签名验证和日历时间
- 各状态独立设置指示灯颜色、亮度和呼吸／常亮模式
- 本地固件签名、写入校验，以及可选的安全启动和安全锁定
- 需要按键确认的操作默认等待 60 秒

## 下载与安装

从 [Releases](https://github.com/XiaoNetwork-Astral/pico-all/releases/latest) 下载 `pico_all-8.2-unsigned.uf2`

> [!WARNING]
> 发布的固件未签名，需要自行签名后再安装；可使用 **PicoForge All → 固件**，选择本地签名密钥进行签名；已开启安全启动的设备必须使用原来的受信任密钥，请妥善离线备份

1. 安装 [picotool 2.3.1+](https://github.com/raspberrypi/picotool/releases)，将其加入 PATH，或设置 `PICOTOOL` 环境变量
2. 打开 PicoForge All → 固件，选择 UF2 文件和 secp256k1 PEM 签名密钥，依次点击“签名”和“刷写”
3. 指示灯闪烁时，按下并松开设备按键（BOOTSEL）

空白设备需要按住 BOOTSEL 再连接电脑；对文件签名不会自动开启安全启动，也不会迁移其他固件中的凭据

命令行用户可从本仓库下载 `firmware.py` 和 `requirements.txt`：

```sh
python -m pip install -r requirements.txt
python firmware.py sign pico_all-8.2-unsigned.uf2 -k .private/my-key.pem --new-key
python firmware.py --help
```

仅首次创建密钥时使用 `--new-key`，后续更新沿用原密钥；普通固件更新会保留已有凭据，重置和擦除操作则会删除相应数据

## 使用

PicoForge All 可管理凭据、PIN、指示灯、审计日志和固件；FIDO 没有默认 PIN，管理已存储的通行密钥前需先设置 PIN；事件记录默认关闭，可在“审计”页面开启；设备校时前记录的事件会显示“时间未知”

| 状态 | 默认颜色 |
| --- | --- |
| 就绪／处理中 | 青色 |
| 等待按键确认 | 黄色 |
| 固件更新 | 蓝色 |
| 成功 | 绿色 |
| 超时／错误 | 红色 |

安全启动和安全锁定属于永久硬件设置，操作前请核对 PicoForge All 中的安全配置说明；擦除 Flash 无法撤销这些设置，也无法消除 RP2350 A2 本身的硬件限制

## 构建

需要 Arm 工具链、Pico SDK 2.3.1、CMake 3.31+ 和 Ninja

```sh
git clone https://github.com/XiaoNetwork-Astral/pico-all.git
cd pico-all
cmake -S . -B build -G Ninja -DPICO_SDK_PATH=/path/to/pico-sdk
cmake --build build
```

默认目标为 RP2350-One，生成未签名的 `build/pico_all.uf2`；协议和存储测试位于 `tests/`

## 许可与致谢

采用 [AGPL-3.0](LICENSE)，基于 Pol Henarejos 及贡献者维护的 [Pico FIDO](https://github.com/polhenarejos/pico-fido)、[Pico OpenPGP](https://github.com/polhenarejos/pico-openpgp)、[Pico HSM](https://github.com/polhenarejos/pico-hsm) 和 [Pico Keys SDK](https://github.com/polhenarejos/pico-keys-sdk)；上游版本见 [upstream.json](upstream.json)
