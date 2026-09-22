# Pico All

English | [中文](README.zh.md)

Turn a **Waveshare RP2350-One** into a USB security key with FIDO2/U2F, OpenPGP/PIV and SmartCard-HSM in one firmware.

## Features

- FIDO2 passkeys and U2F authentication with physical button confirmation.
- OpenPGP and PIV smart-card keys, plus SmartCard-HSM.
- OATH TOTP/HOTP accounts and programmable OTP slots.
- Local firmware signing, verified updates and mode switching with one Python script.
- Optional Secure Boot, OTP device-root protection and permanent signing-key lock.
- Optional Audit logging with signed checkpoints in development builds; disabled by default.

Protocol and security flows have been tested on RP2350-One (A2). [PicoForge All](https://github.com/BlueFunny19/picoforge-all) provides desktop management for this firmware; full end-to-end client compatibility is still being validated.

Organisation attestation supports local key/certificate import and removal without enabling Enterprise Attestation. A FIDO reset clears both kinds of attestation configuration along with FIDO credentials; it does not undo Secure Boot or OTP locks.

## Download and install

Download `pico_all.uf2`, `firmware.py` and `requirements.txt` from [Releases](https://github.com/XiaoNetwork-Astral/pico-all/releases). **We publish unsigned firmware only. Generate your own signing key locally and sign each release before installing it.**

Install Python 3.10+ and [picotool 2.3.1+](https://github.com/raspberrypi/picotool/releases), with `picotool` on PATH. In the download folder:

```sh
python -m pip install -r requirements.txt
python firmware.py sign pico_all.uf2 -k .private/my-key.pem --new-key
python firmware.py flash pico_all.signed.uf2
```

Use `--new-key` only for your first key. Keep the private key local and backed up offline; never upload, sync or commit it. A board with Secure Boot already enabled needs its registered key, not a newly generated one. Signing a file does not enable Secure Boot.

For a new board, hold BOOT while connecting it once to enter BOOTSEL. Once Pico All is installed, the script requests update mode automatically: press and release BOOTSEL when the LED flashes yellow. Existing credentials from other firmware are not migrated.

## Update and manage

Sign later releases with the **same key**, then flash:

```sh
python firmware.py sign pico_all.uf2 -k .private/my-key.pem
python firmware.py flash pico_all.signed.uf2
```

| Command | Action |
| --- | --- |
| `python firmware.py info` | Read installed firmware information; stays in BOOTSEL |
| `python firmware.py device bootsel` | Enter update mode with button confirmation |
| `python firmware.py device reboot` | Return to normal firmware without flashing |
| `python firmware.py security status -s SERIAL` | Read security settings; requests BOOTSEL if needed |
| `python firmware.py --help` | Show commands and examples |

With multiple boards, add `-s SERIAL`. Updates read back the written firmware before restarting and preserve existing Pico All credentials.

## LED

| Light | Meaning |
| --- | --- |
| Green, slow breathing | Idle; brightness 1, about a 2-second cycle |
| Yellow, fast flashing | Press and release BOOTSEL to confirm |
| Blue | Firmware update mode |
| Red flashes | Confirmation timed out |

New U2F credentials work after reconnecting without first unlocking a FIDO2 PIN session. Older U2F credentials may need re-registration for this behavior.

## Optional security setup

`firmware.py security` provides staged setup: **load-key → harden → prepare → enable → prove → lock**. Read `python firmware.py security --help` and each stage's `--help` before proceeding. Every stage requires `-s SERIAL`; writes preview changes unless you add `--apply` and confirm.

Prepare deletes credentials, PINs and settings. Continue directly to Enable without rebooting the application between them. Follow the power-cycle checks at the other stages. OTP device roots initialize only after protected signed boot and remain across updates. Lock permanently fixes the trusted signing key; future updates still work with that key.

RP2350 A2 has [hardware security errata](https://www.raspberrypi.com/news/rp2350-a4-rp2354-and-a-new-hacking-challenge/) that these settings cannot fix.

## Build

Requires Git, an Arm toolchain, Pico SDK 2.3.1, CMake 3.31+ and Ninja. Dependencies are fetched on the first build.

```sh
git clone https://github.com/XiaoNetwork-Astral/pico-all.git
cd pico-all
cmake -S . -B build -G Ninja -DPICO_SDK_PATH=/path/to/pico-sdk
cmake --build build
```

Output: unsigned `build/pico_all.uf2`. The default target is RP2350-One.

## License and credits

[AGPL-3.0](LICENSE). Based on [Pico FIDO](https://github.com/polhenarejos/pico-fido), [Pico OpenPGP](https://github.com/polhenarejos/pico-openpgp), [Pico HSM](https://github.com/polhenarejos/pico-hsm) and [Pico Keys SDK](https://github.com/polhenarejos/pico-keys-sdk) by Pol Henarejos and contributors. Original copyright notices are preserved; pinned revisions are listed in [upstream.json](upstream.json).


### Status-light configuration

Pico All advertises its effective light settings in the PHY response. TLV 0x10
(version 1, steady flag, four colour/brightness pairs) controls Ready, Processing,
Button confirmation and Firmware update. TLV 0x11 (version 1 followed by three
colour/brightness pairs) controls Success, Timeout and Error notifications.
Colours use the SDK palette (0–7); brightness uses 0–255. Defaults are cyan for
Ready/Processing, yellow for confirmation, blue for update, green for success,
and red for timeout/error. Notification timing remains unchanged; Error uses
three 180 ms flashes for internal APDU execution/storage or CTAP processing failures.
Ordinary discovery responses, such as an absent applet, do not flash an error.

Older four-state configurations remain valid. Writes that omit either extension
preserve its stored settings, and successful writes still require physical
confirmation.
