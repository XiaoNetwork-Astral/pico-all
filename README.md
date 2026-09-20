# Pico All

English | [中文](README.zh.md)

FIDO2/U2F, OpenPGP/PIV and SmartCard-HSM in one firmware for the Waveshare RP2350-One

Security provisioning is implemented and tested with an offline OTP model; irreversible on-board validation is still pending.

## Build

Requires an Arm toolchain, Pico SDK 2.3.1, CMake 3.31+ and Ninja

```sh
cmake -S . -B build -G Ninja -DPICO_SDK_PATH=/path/to/pico-sdk
cmake --build build
```

Enter BOOTSEL mode and copy `build/pico_all.uf2` to the board's USB drive; existing credentials from upstream firmware are not migrated

## Use

Green breathing: idle · Yellow flashing: press BOOTSEL · Blue: firmware update mode · Red flashes: confirmation timed out

New U2F credentials work with a button press after reconnecting, independently of the FIDO2 PIN. Legacy U2F credentials still need a PIN-unlocked session; re-register to use the new behavior.

## Firmware tool

Requires Python 3.10+ and [picotool](https://github.com/raspberrypi/picotool) on PATH. One script for board info, local signing, verified flashing and security configuration. Use BOOTSEL for firmware and fuse operations; Prepare and Prove use normal mode.

```sh
python -m pip install -r requirements.txt
python firmware.py -h
python firmware.py menu
```

Use `-h` for a quick reference and `--help` for details and examples, including `python firmware.py security enable --help`. Firmware paths are positional: `python firmware.py security load-key signed.uf2 -s SERIAL`.

Security stages: **Load key → Harden → Prepare → Enable → Prove → Lock**. The menu explains each step; CLI security commands preview changes unless `--apply` is supplied. Power-cycle and test between irreversible stages.

OTP device roots initialize automatically only after signed boot and debug protection are active. First-time setup requires empty credential storage; Prepare explicitly clears credentials, PINs and settings with a board-button confirmation. Existing roots are retained across updates. Lock disables key rotation; keep the signing key backed up offline. Signed BOOTSEL updates remain available.

## License

[AGPL-3.0](LICENSE) · Based on Pico FIDO, Pico OpenPGP, Pico HSM and Pico Keys SDK; authors and pinned revisions are listed in [upstream.json](upstream.json)
