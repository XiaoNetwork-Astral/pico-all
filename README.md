# Pico All

English | [中文](README.zh.md)

Turn a **Waveshare RP2350-One** into a USB security key with FIDO2/U2F, OpenPGP/PIV, SmartCard-HSM and OATH/OTP in one firmware.

## Features

- Passkeys, smart-card keys, one-time passwords and programmable OTP slots
- Desktop management with [PicoForge All](https://github.com/BlueFunny19/picoforge-all)
- Optional security-event logging with signed checkpoints and calendar timestamps
- Per-status light colours, brightness and breathing or steady mode
- Local firmware signing, verified updates and optional Secure Boot / Secure Lock
- Device button confirmation with a default 60-second window

## Download and install

Download `pico_all-8.2-unsigned.uf2` from [Releases](https://github.com/XiaoNetwork-Astral/pico-all/releases/latest).

> [!WARNING]
> Published firmware is unsigned; sign it yourself before installation. You can use **PicoForge All → Firmware** with your local signing key. A device with Secure Boot enabled requires its original trusted key; keep that key backed up offline.

1. Install [picotool 2.3.1+](https://github.com/raspberrypi/picotool/releases) and make it available on PATH, or set the `PICOTOOL` environment variable
2. Open PicoForge All → Firmware, select the UF2 and your secp256k1 PEM signing key, then select **Sign** and **Flash**
3. When the light flashes, press and release the device button (BOOTSEL)

For a blank board, hold BOOTSEL while connecting it. Signing a file does not enable Secure Boot. Credentials from unrelated firmware are not migrated.

For command-line use, download `firmware.py` and `requirements.txt` from this repository:

```sh
python -m pip install -r requirements.txt
python firmware.py sign pico_all-8.2-unsigned.uf2 -k .private/my-key.pem --new-key
python firmware.py --help
```

Use `--new-key` only when creating your first key. Use the same key for later updates. Ordinary Pico All updates preserve stored credentials; reset and erase operations do not.

## Usage

PicoForge All manages credentials, PINs, status lights, event logs and firmware. FIDO has no factory PIN; create one before managing stored passkeys. Event recording is off by default; enable it on the Audit page. Events recorded before clock synchronization show an unknown date.

| Status | Default colour |
| --- | --- |
| Ready / processing | Cyan |
| Button confirmation | Yellow |
| Firmware update | Blue |
| Success | Green |
| Timeout / error | Red |

Secure Boot and Secure Lock are permanent hardware settings. Review the security setup in PicoForge All before applying them; erasing Flash cannot undo them. RP2350 A2 hardware limitations still apply.

## Build

Requires an Arm toolchain, Pico SDK 2.3.1, CMake 3.31+ and Ninja.

```sh
git clone https://github.com/XiaoNetwork-Astral/pico-all.git
cd pico-all
cmake -S . -B build -G Ninja -DPICO_SDK_PATH=/path/to/pico-sdk
cmake --build build
```

Output: unsigned `build/pico_all.uf2`; the default board is RP2350-One. Protocol and storage tests are in `tests/`.

## License and credits

[AGPL-3.0](LICENSE). Based on [Pico FIDO](https://github.com/polhenarejos/pico-fido), [Pico OpenPGP](https://github.com/polhenarejos/pico-openpgp), [Pico HSM](https://github.com/polhenarejos/pico-hsm) and [Pico Keys SDK](https://github.com/polhenarejos/pico-keys-sdk) by Pol Henarejos and contributors. Pinned revisions are listed in [upstream.json](upstream.json).
