# Pico All

[English](README.md) | 中文

将 **Waveshare RP2350-One** 变成 USB 安全密钥，在一份固件中提供 FIDO2/U2F、OpenPGP/PIV 和 SmartCard-HSM。

## 功能

- FIDO2 通行密钥与 U2F 身份验证，支持板上按键确认。
- OpenPGP、PIV 智能卡密钥及 SmartCard-HSM。
- OATH TOTP/HOTP 账户与可编程 OTP 槽位。
- 一个 Python 脚本完成本地签名、校验更新和模式切换。
- 可选的 Secure Boot、OTP 设备根保护与永久签名密钥锁定。
- 开发版本提供可选 Audit 审计日志与签名检查点；默认关闭

已在 RP2350-One（A2）上验证协议和安全配置流程；可通过 [PicoForge All](https://github.com/BlueFunny19/picoforge-all) 管理固件；真实客户端的完整兼容性仍在验证中

组织 Attestation 支持本地导入和清除密钥／证书，无需先启用 Enterprise Attestation。FIDO 重置会同时清除这两类 Attestation 配置及 FIDO 凭据，但不会解除 Secure Boot 或 OTP 锁定。

## 下载与安装

从 [Releases](https://github.com/XiaoNetwork-Astral/pico-all/releases) 下载 `pico_all.uf2`、`firmware.py` 和 `requirements.txt`。**我们只发布未签名固件。请在本地生成自己的签名密钥，每次下载后自行签名再安装。**

安装 Python 3.10+ 和 [picotool 2.3.1+](https://github.com/raspberrypi/picotool/releases)，将 `picotool` 加入 PATH。在下载目录中运行：

```sh
python -m pip install -r requirements.txt
python firmware.py sign pico_all.uf2 -k .private/my-key.pem --new-key
python firmware.py flash pico_all.signed.uf2
```

`--new-key` 仅在首次生成密钥时使用。私钥仅限本地保存，并应离线备份；不要上传、同步或提交到 Git。已经启用 Secure Boot 的板子必须使用已登记的密钥，不能重新生成一把替代。给文件签名不会自动启用 Secure Boot。

新板首次安装时，按住 BOOT 接入电脑，进入 BOOTSEL。安装 Pico All 后，脚本会自动请求切换到更新模式：黄灯闪烁时短按并松开 BOOTSEL 即可。不迁移其他固件中的既有凭据。

## 更新与管理

后续版本继续使用**同一把密钥**签名，再刷入：

```sh
python firmware.py sign pico_all.uf2 -k .private/my-key.pem
python firmware.py flash pico_all.signed.uf2
```

| 命令 | 用途 |
| --- | --- |
| `python firmware.py info` | 查询板内固件信息，完成后停留在 BOOTSEL |
| `python firmware.py device bootsel` | 按键确认后进入更新模式 |
| `python firmware.py device reboot` | 无需刷写，返回正常固件 |
| `python firmware.py security status -s SERIAL` | 查询安全配置，需要时请求进入 BOOTSEL |
| `python firmware.py --help` | 查看命令与示例 |

连接多块板子时加上 `-s SERIAL`。更新会在重启前回读校验，并保留既有 Pico All 凭据。

## 灯光

| 灯光 | 含义 |
| --- | --- |
| 绿色缓慢呼吸 | 待机，亮度 1，约 2 秒一轮 |
| 黄色快速闪烁 | 请短按并松开 BOOTSEL 确认 |
| 蓝色 | 固件更新模式 |
| 红色闪烁 | 确认超时 |

新 U2F 凭据在重新插入后即可使用，无需先通过 FIDO2 PIN 解锁会话；旧 U2F 凭据可能需要重新注册才能使用这一行为。

## 可选安全配置

`firmware.py security` 提供分阶段配置：**load-key → harden → prepare → enable → prove → lock**。开始前请阅读 `python firmware.py security --help` 和各阶段的 `--help`。每个阶段都需要 `-s SERIAL`；写入操作默认只预览，添加 `--apply` 并确认后才会执行。

Prepare 会删除凭据、PIN 和设置，完成后应直接继续 Enable，两者之间不要重启应用。在其他阶段按提示完成断电检查。OTP 设备根只在受保护的签名启动后自动初始化，并在更新后保留。Lock 会永久固定受信任的签名密钥，此后仍可用该密钥更新固件。

RP2350 A2 的[硬件安全勘误](https://www.raspberrypi.com/news/rp2350-a4-rp2354-and-a-new-hacking-challenge/)无法通过上述设置修复。

## 构建

需要 Git、Arm 工具链、Pico SDK 2.3.1、CMake 3.31+ 和 Ninja。首次构建会下载依赖。

```sh
git clone https://github.com/XiaoNetwork-Astral/pico-all.git
cd pico-all
cmake -S . -B build -G Ninja -DPICO_SDK_PATH=/path/to/pico-sdk
cmake --build build
```

产物为未签名的 `build/pico_all.uf2`，默认目标板为 RP2350-One。

## 许可证与致谢

[AGPL-3.0](LICENSE)。基于 Pol Henarejos 及贡献者开发的 [Pico FIDO](https://github.com/polhenarejos/pico-fido)、[Pico OpenPGP](https://github.com/polhenarejos/pico-openpgp)、[Pico HSM](https://github.com/polhenarejos/pico-hsm) 和 [Pico Keys SDK](https://github.com/polhenarejos/pico-keys-sdk)。保留原始版权声明，引用版本见 [upstream.json](upstream.json)。
