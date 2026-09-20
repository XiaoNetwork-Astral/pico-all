#!/usr/bin/env python3
"""Local signing, verified UF2 updates, and staged RP2350 security."""
# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

try:
    from rich.console import Console
    from rich.prompt import Confirm, Prompt
    from rich.table import Table
except ImportError:
    raise SystemExit("Install dependencies: python -m pip install -r requirements.txt")

console = Console(highlight=False)
ROOT = Path(__file__).resolve().parent
DEFAULT_KEY = ROOT / ".private" / "firmware-signing.pem"


class FirmwareError(Exception):
    pass


def tool_path(value: str | None) -> str:
    candidate = value or os.environ.get("PICOTOOL") or shutil.which("picotool")
    if not candidate:
        for name in ("picotool.exe", "picotool"):
            local = ROOT / name
            if local.is_file():
                candidate = str(local)
                break
    if not candidate:
        raise FirmwareError("picotool not found. Add it to PATH or use --picotool PATH.")
    resolved = shutil.which(candidate) or candidate
    if not Path(resolved).is_file():
        raise FirmwareError("picotool not found. Check --picotool or PICOTOOL.")
    return str(Path(resolved).resolve())


def run(tool: str, args: list[str], label: str, timeout: int = 120) -> str:
    with console.status(label):
        try:
            result = subprocess.run([tool, *args], capture_output=True, text=True,
                                    errors="replace", timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            raise FirmwareError("Device did not finish in time. Reconnect in BOOTSEL mode and retry.") from None
        except OSError:
            raise FirmwareError("Could not start picotool. Check its installation.") from None
    output = result.stdout + result.stderr
    if result.returncode:
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        detail = "\n".join(lines[-6:]) or "picotool failed."
        raise FirmwareError(detail)
    return output


def uf2_file(value: str | Path) -> Path:
    path = Path(value).expanduser().resolve()
    if not path.is_file() or path.suffix.lower() != ".uf2":
        raise FirmwareError("Choose an existing .uf2 firmware file.")
    return path


def signing_key(path: Path, create: bool) -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    if create:
        if path.exists():
            raise FirmwareError("Key already exists. Remove --new-key to use it.")
        key = ec.generate_private_key(ec.SECP256K1())
        pem = key.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.TraditionalOpenSSL,
                                serialization.NoEncryption())
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(pem)
        console.print("Created local signing key: " + str(path), style="green", markup=False)
        console.print("Keep this key private and back it up offline.", style="dim")
    if not path.is_file():
        raise FirmwareError("Key not found. Use --new-key to create one.")
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (ValueError, TypeError):
        raise FirmwareError("Use an unencrypted secp256k1 private key in PEM format.") from None
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256K1):
        raise FirmwareError("Signing requires a secp256k1 private key.")


def approved(message: str, yes: bool) -> None:
    if yes:
        return
    if not sys.stdin.isatty():
        raise FirmwareError("Confirmation required. Review the command, then add --yes.")
    if not Confirm.ask(message, default=False):
        raise FirmwareError("Cancelled.")


def sign(tool: str, firmware: str, key_name: str, output: str | None,
         new_key: bool = False, yes: bool = False) -> Path:
    source = uf2_file(firmware)
    key = Path(key_name).expanduser().resolve()
    destination = Path(output).expanduser().resolve() if output else source.with_name(source.stem + ".signed.uf2")
    if destination.suffix.lower() != ".uf2":
        raise FirmwareError("Output must end in .uf2.")
    if source == destination or key in (source, destination):
        raise FirmwareError("Firmware, signed output, and key must use different paths.")
    if not destination.parent.is_dir():
        raise FirmwareError("Output folder does not exist.")
    if destination.exists():
        approved("Replace the existing signed firmware?", yes)
    run(tool, ["info", "-b", str(source)], "Checking firmware...")
    signing_key(key, new_key)
    # Publish only after picotool has verified the new signature.
    with tempfile.TemporaryDirectory(prefix=".firmware-sign-", dir=destination.parent) as directory:
        temporary = Path(directory) / "signed.uf2"
        run(tool, ["seal", "--sign", str(source), str(temporary), str(key)], "Signing firmware...")
        info = run(tool, ["info", "-b", str(temporary)], "Verifying signature...")
        if not re.search(r"signature:\s+verified\b", info, re.IGNORECASE):
            raise FirmwareError("Signature verification failed. Output was not replaced.")
        os.replace(temporary, destination)
    console.print("Signed and verified: " + str(destination), style="green", markup=False)
    return destination


def selection(serial: str | None) -> list[str]:
    return ["--ser", serial] if serial else []


def board_info(tool: str, serial: str | None) -> None:
    console.print("Connect in BOOTSEL mode: hold BOOTSEL while plugging in.", style="dim")
    text = run(tool, ["info", "-b", "-l", "-d", *selection(serial)], "Reading board firmware...", 30)
    table = Table(title="Board firmware", show_header=False, box=None, padding=(0, 2))
    table.add_column(style="cyan")
    table.add_column(overflow="fold")
    labels = {"name": "Firmware", "version": "Version", "signature": "Signature",
              "pico_board": "Board", "sdk version": "SDK", "build date": "Built",
              "type": "Chip", "chipid": "Serial", "flash size": "Flash",
              "secure boot": "Secure boot"}
    seen = set()
    from rich.text import Text
    for line in text.splitlines():
        match = re.match(r"\s*([^:]+):\s+(\S.*)", line)
        if match:
            label, value = match.groups()
            label = label.strip().lower()
            if label in labels and label not in seen:
                table.add_row(Text(labels[label]), Text(value.strip()))
                seen.add(label)
    if not table.row_count:
        raise FirmwareError("No board information returned. Check BOOTSEL mode and --serial.")
    console.print(table)
    console.print("Board remains in BOOTSEL mode. Reconnect normally to start it.", style="dim")


def flash(tool: str, firmware: str, serial: str | None, yes: bool = False) -> None:
    source = uf2_file(firmware)
    run(tool, ["info", "-b", str(source)], "Checking firmware...")
    console.print("Firmware: " + str(source), markup=False)
    console.print("Connect in BOOTSEL mode: hold BOOTSEL while plugging in.", style="dim")
    approved("Flash this firmware and restart the board?", yes)
    # picotool refuses ambiguous targets. Keep its partition checks and verify
    # every write; never use erase, ignore-partitions, or OTP commands.
    run(tool, ["load", "-v", "-x", str(source), *selection(serial)], "Flashing and verifying...", 180)
    console.print("Flashed and verified. Board restarted.", style="green")


# RP2350 predefined OTP layout (datasheet 13.10). Only public boot rows are
# accessible through this host interface; device-root pages are never dumped.
CRIT_ROWS = tuple(range(0x40, 0x48))
FLAGS_ROWS = (0x4b, 0x4c, 0x4d)
BOOT_LOCKS = (0xf83, 0xf85)
HARDEN_BITS = 0x74  # debug disabled, glitch detector enabled, sensitivity 3
BOOT_LOCK = 0x151515  # Secure/Non-secure/BOOTSEL read-only, three copies


def vote(values: list[int], threshold: int) -> int:
    return sum(1 << bit for bit in range(24)
               if sum(bool(value & (1 << bit)) for value in values) >= threshold)


class BootOtp:
    """Small picotool transport. Simulation replaces this boundary, not policy."""
    def __init__(self, tool: str, serial: str):
        if not re.fullmatch(r"[0-9a-fA-F]{16}", serial or ""):
            raise FirmwareError("Enter the board's 16-digit serial number.")
        self.tool, self.serial = tool, serial.upper()

    def read(self, row: int, ecc: bool = False) -> int:
        text = run(self.tool, ["otp", "get", "-e" if ecc else "-r", "-c", "1", "-n",
                              hex(row), *selection(self.serial)], "Reading security state...", 30)
        found = re.findall(r"\bVALUE\s+(0x[0-9a-fA-F]+)\b", text)
        if len(found) != 1:
            raise FirmwareError(f"Could not read OTP row {row:#x}. No changes made by this read.")
        value = int(found[0], 16)
        if value > (0xffff if ecc else 0xffffff):
            raise FirmwareError("Unexpected OTP value. Check the picotool version.")
        return value

    def write(self, row: int, value: int, ecc: bool = False) -> None:
        # Policy calls only boot-key words, CRIT1, BOOT_FLAGS1 and their locks.
        allowed = (ecc and 0x80 <= row < 0xc0) or (not ecc and row in (*CRIT_ROWS, *FLAGS_ROWS, *BOOT_LOCKS))
        if not allowed:
            raise FirmwareError("Unsupported OTP write.")
        run(self.tool, ["otp", "set", "-e" if ecc else "-r", "-c", "1", hex(row), hex(value),
                        *selection(self.serial)], "Programming security settings...", 30)
        if self.read(row, ecc) != value:
            raise FirmwareError(f"OTP verification failed at {row:#x}. Stop and read status before retrying.")

    def board(self) -> str:
        text = run(self.tool, ["info", "-d", *selection(self.serial)], "Checking target board...", 30)
        if "RP2350" not in text or "Multiple RP-series" in text:
            raise FirmwareError("Connect exactly the selected RP2350 in BOOTSEL mode.")
        return text


def boot_state(otp: BootOtp) -> dict:
    critical = [otp.read(row) for row in CRIT_ROWS]
    flags = [otp.read(row) for row in FLAGS_ROWS]
    locks = [otp.read(row) for row in BOOT_LOCKS]
    # Lock0 can gate access with hardware keys; this workflow doesn't own them.
    key_locks = [otp.read(0xf82), otp.read(0xf84)]
    fps = []
    for slot in range(4):
        try:
            words = [otp.read(0x80 + 16 * slot + i, True) for i in range(16)]
            fps.append(b"".join(word.to_bytes(2, "little") for word in words))
        except FirmwareError:
            # Keep an unreadable slot distinct from a blank slot. A torn unused
            # slot must not prevent provisioning a different, readable slot.
            fps.append(None)
    flag = vote(flags, 2)
    return dict(critical=critical, flags=flags, locks=locks, key_locks=key_locks,
                crit=vote(critical, 3), valid=flag & 15, revoked=(flag >> 8) & 15, fps=fps)


def show_security(state: dict) -> None:
    table = Table(title="RP2350 security", show_header=False, box=None)
    crit = state["crit"]
    table.add_row("Secure Boot fuse", "Enabled" if crit & 1 else "Disabled")
    table.add_row("Debug fuse", "Disabled" if crit & 4 else "Enabled")
    table.add_row("Glitch detector", f"Enabled, sensitivity {(crit >> 5) & 3}" if crit & 16 else "Disabled")
    for i, fp in enumerate(state["fps"]):
        label = "Revoked" if state["revoked"] & (1 << i) else ("Trusted" if state["valid"] & (1 << i) else "Unused")
        table.add_row(f"Boot key {i}", "Unreadable / " + label if fp is None else
                      label + (" / " + fp.hex() if any(fp) else ""))
    table.add_row("Boot page locks", ", ".join(f"{lock:06x}" for lock in state["locks"]))
    console.print(table)
    console.print("Fuse settings take effect after a full power cycle.", style="dim")


def firmware_fingerprint(tool: str, path: Path) -> bytes:
    text = run(tool, ["info", "-m", str(path)], "Verifying signed firmware...")
    blocks = re.split(r"Metadata Block \d+", text)
    signed = [block for block in blocks if re.search(r"signature:\s+verified\b", block)]
    # Reject ambiguous multi-image inputs. The tool manages one RP2350 Arm image.
    if len(signed) != 1 or not re.search(r"target chip:\s+RP2350\b", signed[0]) or not re.search(r"image type:\s+ARM Secure\b", signed[0]):
        raise FirmwareError("Choose one verified, signed RP2350 Arm firmware image.")
    match = re.search(r"public key:\s+([0-9a-fA-F]{128})\b", signed[0])
    if not match:
        raise FirmwareError("Could not read the firmware signing public key.")
    # picotool hashes the 64-byte big-endian X || Y public key, without SEC1 prefix.
    return hashlib.sha256(bytes.fromhex(match[1])).digest()


def security_plan(otp: BootOtp, state: dict, action: str, fp: bytes, slot: int) -> list[tuple[int, int, bool]]:
    if slot not in range(4) or len(fp) != 32 or not any(fp):
        raise FirmwareError("Invalid boot key or slot.")
    if any(state["key_locks"]):
        raise FirmwareError("Boot pages use an existing hardware access-key policy.")
    writes = []
    def raw(row: int, old: int, bits: int):
        if old | bits != old:
            writes.append((row, old | bits, False))
    trusted = state["valid"] & ~state["revoked"] & 15
    matches = [i for i in range(4) if state["fps"][i] == fp and trusted & (1 << i)]
    if action == "load-key":
        if any(value & (1 << (slot + 8)) for value in state["flags"]):
            raise FirmwareError("This key slot is revoked. Choose an unused slot.")
        for i in range(16):
            row = 0x80 + 16 * slot + i
            wanted = int.from_bytes(fp[2*i:2*i+2], "little")
            if otp.read(row):
                if otp.read(row, True) != wanted:
                    raise FirmwareError("This key slot contains different or incomplete data. Choose another slot.")
            elif wanted:
                writes.append((row, wanted, True))
        # KEY_VALID is programmed only AFTER all fingerprint words read back.
        for row, old in zip(FLAGS_ROWS, state["flags"]):
            raw(row, old, 1 << slot)
    else:
        if len(matches) != 1:
            raise FirmwareError("The firmware signing key must match exactly one trusted OTP slot.")
        if action == "harden":
            for row, old in zip(CRIT_ROWS, state["critical"]):
                raw(row, old, HARDEN_BITS)
        elif action == "enable":
            if any(value & HARDEN_BITS != HARDEN_BITS for value in state["critical"]):
                raise FirmwareError("Run Harden and verify a power-cycle boot first.")
            if any(not value & (1 << matches[0]) for value in state["flags"]):
                raise FirmwareError("Finish Load key before enabling Secure Boot.")
            for row, old in zip(CRIT_ROWS, state["critical"]):
                raw(row, old, 1)
        elif action == "lock":
            if any(value & 0x75 != 0x75 for value in state["critical"]):
                raise FirmwareError("Enable Secure Boot and verify a power-cycle boot first.")
            if trusted != 1 << matches[0]:
                raise FirmwareError("More than one key is trusted. This lock workflow requires a single signing key.")
            revoke = (15 ^ trusted) << 8
            for row, old in zip(FLAGS_ROWS, state["flags"]):
                raw(row, old, revoke)
            for row, old in zip(BOOT_LOCKS, state["locks"]):
                if old & ~BOOT_LOCK:
                    raise FirmwareError("Boot pages have incompatible existing locks.")
                effective = vote([(old >> shift) & 255 for shift in (0, 8, 16)], 2)
                if effective != 0x15:
                    raw(row, old, BOOT_LOCK)
        else:
            raise FirmwareError("Unknown security action.")
    for row, _, _ in writes:
        lock_index = 1 if 0x80 <= row < 0xc0 or row == 0xf85 else 0
        if vote([(state["locks"][lock_index] >> shift) & 255 for shift in (0, 8, 16)], 2) & 0x30:
            raise FirmwareError("BOOTSEL cannot modify this locked page. Read status before continuing.")
    return writes


def boot_proof_path(serial: str) -> Path:
    return ROOT / ".private" / ("boot-check-" + serial.upper() + ".json")


def management(serial: str, command: list[int]) -> bytes:
    from smartcard.System import readers
    from smartcard.Exceptions import CardConnectionException
    BootOtp("", serial)
    connections, matches = [], []
    try:
        for reader in readers():
            if "Pico All" not in str(reader):
                continue
            connection = reader.createConnection()
            connection.connect()
            connections.append(connection)
            data, sw1, sw2 = connection.transmit([0, 0xa4, 4, 0, 8, 0xa0, 0x58, 0x3f, 0xc1, 0x9b, 0x7e, 0x4f, 0x21])
            if (sw1, sw2) == (0x90, 0) and len(data) == 12 and bytes(data[4:]).hex().upper() == serial.upper():
                matches.append(connection)
        if len(matches) != 1:
            raise FirmwareError("Connect exactly the selected board in normal mode.")
        data, sw1, sw2 = matches[0].transmit(command)
        if (sw1, sw2) != (0x90, 0):
            raise FirmwareError(f"Board declined the operation ({sw1:02X}{sw2:02X}). Check its state or button confirmation.")
        return bytes(data)
    except CardConnectionException:
        raise FirmwareError("Could not communicate with the board. Reconnect normally and retry.") from None
    finally:
        for connection in connections:
            connection.disconnect()


def prepare_storage(serial: str, apply: bool) -> None:
    data = management(serial, [0x80, 0x1e, 6, 0, 0])
    if len(data) != 7 or data[0] != 1 or data[1] != 0 or int.from_bytes(data[3:], "big") & 1:
        raise FirmwareError("Preparation is allowed only before OTP root initialization and Secure Boot.")
    console.print("Erase all application credentials, PINs and settings, then return to BOOTSEL.", style="yellow")
    console.print("Firmware and OTP are retained. Do not reconnect normally before Enable.", style="dim")
    if not apply:
        console.print("Preview only. Add --apply to confirm preparation.", style="cyan")
        return
    phrase = "ERASE " + serial.upper()
    if not sys.stdin.isatty() or Prompt.ask("Type " + phrase) != phrase:
        raise FirmwareError("Cancelled.")
    console.print("Press and release BOOTSEL when the LED flashes yellow.", style="yellow")
    management(serial, [0x80, 0x1d, 0, 2, 0])
    console.print("Preparation requested. Wait for the BOOTSEL drive; Enable will verify that storage is empty.", style="green")


def require_empty_storage(tool: str, serial: str, source: Path) -> None:
    metadata = run(tool, ["info", "-m", str(source)], "Checking storage layout...")
    match = re.search(r"partition 1 \([^\n]*?\):\s+([0-9a-fA-F]{8})->([0-9a-fA-F]{8})", metadata)
    if not match:
        raise FirmwareError("Could not identify the Pico All data partition.")
    start, end = [int(part, 16) for part in match.groups()]
    # This workflow is intentionally bounded to the RP2350-One's 4 MiB flash.
    if start < 0x102000 or end != 0x400000 or start >= end - 0x2000 or start % 4096:
        raise FirmwareError("Unsupported credential storage layout. No OTP changes made.")
    start += 0x10000000
    end += 0x10000000 - 0x2000  # SDK reserves the last two sectors.
    private = ROOT / ".private"
    private.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="storage-check-", dir=private) as directory:
        target = Path(directory) / "storage.bin"
        run(tool, ["save", "-r", hex(start), hex(end), str(target), "-t", "bin", *selection(serial)],
            "Checking empty credential storage...", 60)
        if target.stat().st_size != end - start:
            raise FirmwareError("Could not read the complete credential area.")
        with target.open("rb") as handle:
            while chunk := handle.read(65536):
                if chunk != b"\xff" * len(chunk):
                    raise FirmwareError("Credential storage is not empty. Run security prepare before Enable.")


def prove_boot(tool: str, serial: str, firmware: str) -> None:
    # Read-only APDUs. The saved record is a local workflow check, not attestation.
    source = uf2_file(firmware)
    firmware_fingerprint(tool, source)
    BootOtp(tool, serial)  # Validate serial before constructing a local path.
    data = management(serial, [0x80, 0x1e, 6, 0, 0])
    if len(data) != 7 or data[0] != 1:
        raise FirmwareError("Update to firmware with OTP status support first.")
    critical = int.from_bytes(data[3:], "big")
    if data[1] != 1 or data[2] not in range(56, 59) or critical & 0x75 != 0x75:
        raise FirmwareError("Signed boot, hardening and OTP root are not all active.")
    matched = dict(serial=serial.upper(), sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                   critical=critical, root_page=data[2])
    path = boot_proof_path(serial)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(matched, indent=2) + "\n", encoding="utf-8")
    console.print("Secure boot and OTP root are active. Boot check saved.", style="green")


def security(tool: str, action: str, serial: str, firmware: str | None = None,
             slot: int = 0, apply: bool = False) -> None:
    if action == "prepare":
        prepare_storage(serial, apply)
        return
    if action == "prove":
        if not firmware:
            raise FirmwareError("Choose the signed firmware with --firmware.")
        prove_boot(tool, serial, firmware)
        return
    otp = BootOtp(tool, serial)
    board = otp.board()
    state = boot_state(otp)
    show_security(state)
    if action == "status":
        return
    if not firmware:
        raise FirmwareError("Choose the signed firmware with --firmware.")
    source = uf2_file(firmware)
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    fp = firmware_fingerprint(tool, source)
    plan = security_plan(otp, state, action, fp, slot)
    console.print("Signing key: " + fp.hex(), markup=False)
    for row, value, ecc in plan:
        console.print(f"  {'ECC' if ecc else 'RAW'}  {row:#05x}  ->  {value:#08x}", style="dim")
    if not plan:
        console.print("This stage is already complete.", style="green")
        return
    effects = {
        "load-key": "Permanently register this signing key. Secure Boot remains unchanged.",
        "harden": "Permanently disable debug and enable maximum glitch sensitivity. Power-cycle and test before Enable.",
        "enable": "Permanently require signed firmware. OTP roots initialize on a protected boot with EMPTY credential storage.",
        "lock": "Permanently revoke every other signing-key slot and make boot configuration read-only. Key rotation ends here.",
    }
    console.print(effects[action], style="yellow")
    console.print("Signed BOOTSEL updates remain available. Keep your signing key backed up offline.", style="dim")
    if not apply:
        console.print("Preview only. Add --apply to review and confirm this stage.", style="cyan")
        return
    if action == "enable" and not state["crit"] & 1:
        require_empty_storage(tool, serial, source)
    # Verify the exact signed file is installed before any irreversible stage.
    run(tool, ["verify", str(source), *selection(serial)], "Checking installed firmware...", 60)
    if action == "lock":
        try:
            proof = json.loads(boot_proof_path(serial).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise FirmwareError("Run the normal-mode boot check (security prove) before Lock.") from None
        if proof.get("serial") != serial.upper() or proof.get("sha256") != hashlib.sha256(source.read_bytes()).hexdigest():
            raise FirmwareError("Boot check does not match this board and firmware. Run security prove again.")
        if not re.search(r"secure boot:\s+1\b", board, re.I):
            raise FirmwareError("Secure Boot is not latched. Power-cycle and repeat the boot check.")
    if not sys.stdin.isatty():
        raise FirmwareError("Security writes require an interactive terminal. No --yes override.")
    if action in ("harden", "enable") and not Confirm.ask("Has this signed firmware booted and worked after the previous stage's power cycle?", default=False):
        raise FirmwareError("Cancelled. Test the current stage before continuing.")
    phrase = action.upper() + " " + serial.upper()
    if Prompt.ask("Type " + phrase) != phrase:
        raise FirmwareError("Cancelled.")
    # Re-read after the user reviews the plan; do not burn a stale plan.
    if boot_state(otp) != state:
        raise FirmwareError("Security state changed during confirmation. Read status and try again.")
    if hashlib.sha256(source.read_bytes()).hexdigest() != source_hash:
        raise FirmwareError("Firmware file changed during confirmation. Start this stage again.")
    run(tool, ["verify", str(source), *selection(serial)], "Rechecking installed firmware...", 60)
    for row, value, ecc in plan:
        otp.write(row, value, ecc)
    console.print("Stage programmed and read back. Fully unplug before testing the next stage.", style="green")


def security_menu(tool: str) -> None:
    console.print("Security: status / load-key / harden / prepare / enable / prove / lock", style="cyan")
    action = Prompt.ask("Stage", choices=["status", "load-key", "harden", "prepare", "enable", "prove", "lock"], default="status")
    serial = Prompt.ask("Board serial")
    source = None if action in ("status", "prepare") else Prompt.ask("Signed firmware UF2").strip().strip('"')
    slot = int(Prompt.ask("Boot key slot", choices=["0", "1", "2", "3"], default="0")) if action == "load-key" else 0
    security(tool, action, serial, source, slot, apply=action not in ("status", "prove"))


def parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--picotool", help="picotool executable path")
    top = argparse.ArgumentParser(description="Sign, inspect, update, and secure board firmware.", parents=[common])
    commands = top.add_subparsers(dest="command")
    # Separate defaults let --picotool work before or after the subcommand.
    local = argparse.ArgumentParser(add_help=False)
    local.add_argument("--picotool", default=argparse.SUPPRESS, help="picotool executable path")
    info = commands.add_parser("info", parents=[local], help="Read board firmware in BOOTSEL mode")
    info.add_argument("--serial", help="Target board serial number")
    signer = commands.add_parser("sign", parents=[local], help="Sign a UF2 locally")
    signer.add_argument("firmware", help="Input UF2")
    signer.add_argument("--key", default=str(DEFAULT_KEY), help="secp256k1 PEM private key")
    signer.add_argument("--new-key", action="store_true", help="Create the key; never overwrite an existing key")
    signer.add_argument("-o", "--output", help="Signed UF2 path")
    signer.add_argument("-y", "--yes", action="store_true", help="Allow replacing an existing output")
    updater = commands.add_parser("flash", parents=[local], help="Flash a UF2, verify, and restart")
    updater.add_argument("firmware", help="Firmware UF2")
    updater.add_argument("--serial", help="Target board serial number")
    updater.add_argument("-y", "--yes", action="store_true", help="Skip the flash confirmation")
    secure = commands.add_parser("security", parents=[local], help="Inspect or configure RP2350 security")
    secure.add_argument("action", choices=["status", "load-key", "harden", "prepare", "enable", "prove", "lock"])
    secure.add_argument("--serial", required=True, help="Exact target board serial")
    secure.add_argument("--firmware", help="The signed UF2 installed on the board")
    secure.add_argument("--slot", type=int, choices=range(4), default=0)
    secure.add_argument("--apply", action="store_true", help="Allow interactive confirmation; default is preview only")
    return top


def menu(tool: str) -> None:
    console.print("Pico All Firmware", style="bold cyan")
    while True:
        console.print("\n1  Board info\n2  Sign firmware\n3  Flash firmware\n4  Security\n0  Exit")
        choice = Prompt.ask("Action", choices=["1", "2", "3", "4", "0"], default="0")
        if choice == "0":
            return
        try:
            if choice == "1":
                board_info(tool, Prompt.ask("Board serial (blank for auto)", default="") or None)
            elif choice == "2":
                source = Prompt.ask("Firmware UF2").strip().strip('"')
                key = Prompt.ask("Private key PEM", default=str(DEFAULT_KEY)).strip().strip('"')
                create = not Path(key).expanduser().exists() and Confirm.ask("Create this signing key?", default=True)
                sign(tool, source, key, None, create)
            elif choice == "4":
                security_menu(tool)
            else:
                source = Prompt.ask("Firmware UF2").strip().strip('"')
                serial = Prompt.ask("Board serial (blank for auto)", default="") or None
                flash(tool, source, serial)
        except (FirmwareError, OSError) as error:
            console.print(str(error), style="red", markup=False)


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        tool = tool_path(arguments.picotool)
        if arguments.command == "info":
            board_info(tool, arguments.serial)
        elif arguments.command == "sign":
            sign(tool, arguments.firmware, arguments.key, arguments.output, arguments.new_key, arguments.yes)
        elif arguments.command == "flash":
            flash(tool, arguments.firmware, arguments.serial, arguments.yes)
        elif arguments.command == "security":
            security(tool, arguments.action, arguments.serial, arguments.firmware, arguments.slot, arguments.apply)
        elif sys.stdin.isatty():
            menu(tool)
        else:
            parser().print_help()
        return 0
    except KeyboardInterrupt:
        console.print("Interrupted. If flashing, reconnect in BOOTSEL mode and retry.", style="yellow")
        return 130
    except (FirmwareError, OSError, EOFError) as error:
        console.print(str(error) or "Input closed.", style="red", markup=False)
        return 1
    except ImportError:
        console.print("Install dependencies: python -m pip install -r requirements.txt", style="red")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
