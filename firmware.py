#!/usr/bin/env python3
"""Local firmware signing, board information, and verified UF2 updates."""
# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import argparse
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


def parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--picotool", help="picotool executable path")
    top = argparse.ArgumentParser(description="Sign, inspect, and update board firmware.", parents=[common])
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
    return top


def menu(tool: str) -> None:
    console.print("Pico All Firmware", style="bold cyan")
    while True:
        console.print("\n1  Board info\n2  Sign firmware\n3  Flash firmware\n0  Exit")
        choice = Prompt.ask("Action", choices=["1", "2", "3", "0"], default="0")
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
