# Pico All

English | [中文](README.zh.md)

FIDO2/U2F, OpenPGP/PIV and SmartCard-HSM in one firmware for the Waveshare RP2350-One

Development build: hardware OTP provisioning and Secure Boot / Secure Lock are disabled; do not use it for important credentials yet

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

## License

[AGPL-3.0](LICENSE) · Based on Pico FIDO, Pico OpenPGP, Pico HSM and Pico Keys SDK; authors and pinned revisions are listed in [upstream.json](upstream.json)
