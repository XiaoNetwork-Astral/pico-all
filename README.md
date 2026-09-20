# Pico All

English | [中文](README.zh.md)

FIDO2/U2F, OpenPGP/PIV and SmartCard-HSM in one firmware for the Waveshare RP2350-One

OTP initialization, Secure Boot / Lock and signed updates have been tested on an RP2350-One (A2). Its [hardware security errata](https://www.raspberrypi.com/news/rp2350-a4-rp2354-and-a-new-hacking-challenge/) still apply.

## Build

Requires an Arm toolchain, Pico SDK 2.3.1, CMake 3.31+ and Ninja

```sh
cmake -S . -B build -G Ninja -DPICO_SDK_PATH=/path/to/pico-sdk
cmake --build build
```

Enter BOOTSEL mode and copy `build/pico_all.uf2` to the board's USB drive. With Secure Boot enabled, sign it with the registered key first. Existing credentials from upstream firmware are not migrated.

## Use

Green breathing: idle · Yellow flashing: press BOOTSEL · Blue: firmware update mode · Red flashes: confirmation timed out

New U2F credentials work with a button press after reconnecting, independently of the FIDO2 PIN. Legacy U2F credentials still need a PIN-unlocked session; re-register to use the new behavior.

## Firmware tool

Requires Python 3.10+ and [picotool](https://github.com/raspberrypi/picotool) on PATH. One script for board info, local signing, verified flashing and security configuration. Commands request BOOTSEL when needed; press and release the button when the LED flashes yellow. Prepare and Prove use normal mode.

```sh
python -m pip install -r requirements.txt
python firmware.py -h
```

Use `-h` for a quick reference and `--help` for details and examples, including `python firmware.py security enable --help`. Firmware paths are positional: `python firmware.py security load-key signed.uf2 -s SERIAL`.

Use `python firmware.py device bootsel` to enter update mode, and `python firmware.py device reboot` to return to firmware without flashing or pressing RESET. With multiple boards, add `-s SERIAL`. Do not reboot between Prepare and Enable.

Security stages: **Load key → Harden → Prepare → Enable → Prove → Lock**. Each command explains its stage in `--help`; security commands preview changes unless `--apply` is supplied. Power-cycle and test between irreversible stages.

OTP device roots initialize automatically only after signed boot and debug protection are active. First-time setup requires empty credential storage; Prepare explicitly clears credentials, PINs and settings with a board-button confirmation. Existing roots are retained across updates. Lock disables key rotation; keep the signing key backed up offline. Signed BOOTSEL updates remain available.

## License

[AGPL-3.0](LICENSE) · Based on Pico FIDO, Pico OpenPGP, Pico HSM and Pico Keys SDK; authors and pinned revisions are listed in [upstream.json](upstream.json)
