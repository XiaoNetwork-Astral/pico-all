"""Firmware tool regression tests; no USB device is accessed."""
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from rich.console import Console
import firmware


class FirmwareToolTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.folder = Path(self.directory.name)
        self.source = self.folder / 'input with spaces.uf2'
        self.source.write_bytes(b'test firmware')
        self.key = self.folder / 'key.pem'
        self.output = self.folder / 'signed.uf2'
        self.capture = io.StringIO()
        self.console = patch.object(firmware, 'console', Console(file=self.capture))
        self.console.start()
        self.addCleanup(self.console.stop)

    def test_key_creation_never_overwrites_and_uses_rp2350_curve(self):
        firmware.signing_key(self.key, True)
        original = self.key.read_bytes()
        loaded = serialization.load_pem_private_key(original, None)
        self.assertIsInstance(loaded.curve, ec.SECP256K1)
        with self.assertRaises(firmware.FirmwareError):
            firmware.signing_key(self.key, True)
        self.assertEqual(self.key.read_bytes(), original)
        self.assertNotIn('BEGIN EC PRIVATE KEY', self.capture.getvalue())

    def test_rejects_wrong_curve(self):
        key = ec.generate_private_key(ec.SECP256R1())
        self.key.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.TraditionalOpenSSL,
                            serialization.NoEncryption()))
        with self.assertRaisesRegex(firmware.FirmwareError, 'secp256k1'):
            firmware.signing_key(self.key, False)

    def test_failed_verification_preserves_output(self):
        firmware.signing_key(self.key, True)
        self.output.write_bytes(b'previous signed firmware')
        def backend(tool, args, label, **kwargs):
            if args[0] == 'seal':
                Path(args[3]).write_bytes(b'unverified output')
            return 'signature: none'
        with patch.object(firmware, 'run', side_effect=backend):
            with self.assertRaisesRegex(firmware.FirmwareError, 'verification failed'):
                firmware.sign('picotool', str(self.source), str(self.key), str(self.output), yes=True)
        self.assertEqual(self.output.read_bytes(), b'previous signed firmware')
        self.assertEqual(self.source.read_bytes(), b'test firmware')

    def test_input_and_key_cannot_be_output(self):
        with patch.object(firmware, 'run') as backend:
            with self.assertRaises(firmware.FirmwareError):
                firmware.sign('picotool', str(self.source), str(self.key), str(self.source), yes=True)
            self.assertFalse(backend.called)

    def test_flash_failure_is_not_reported_as_success(self):
        def backend(tool, args, label, *extra):
            if args[0] == 'load':
                self.assertEqual(args, ['load', '-v', '-x', str(self.source.resolve()), '--ser', 'BOARD123'])
                raise firmware.FirmwareError('Write failed')
            return 'firmware metadata'
        with patch.object(firmware, 'run', side_effect=backend), \
             patch.object(firmware, 'ensure_bootsel', return_value='BOARD123'):
            with self.assertRaisesRegex(firmware.FirmwareError, 'Write failed'):
                firmware.flash('picotool', str(self.source), 'BOARD123', yes=True)
        self.assertNotIn('Flashed and verified', self.capture.getvalue())

    def test_otp_arguments_follow_picotool_order_and_verify_returned_row(self):
        otp = firmware.BootOtp('picotool', '0011223344556677')
        for ecc, mode, row in [(False, '-r', 0x40), (True, '-e', 0x80)]:
            with patch.object(firmware, 'run', return_value=f'ROW {row:#06x}: TEST\n VALUE 0x0000') as backend:
                self.assertEqual(otp.read(row, ecc), 0)
                self.assertEqual(backend.call_args.args[1],
                    ['otp', 'get', '-c', '1', mode, '-n', '--ser', otp.serial, hex(row)])
            with patch.object(firmware, 'run') as backend, patch.object(otp, 'read', return_value=1):
                otp.write(row, 1, ecc)
                self.assertEqual(backend.call_args.args[1],
                    ['otp', 'set', '-c', '1', mode, hex(row), '0x1', '--ser', otp.serial])
        with patch.object(firmware, 'run', return_value='ROW 0x0041\n\n    VALUE 0x000000\n'):
            self.assertEqual(otp.read(0x41), 0)
        for output in ['ROW 0x0001: CHIPID\n VALUE 0x0000',
                       'ROW 0x0001: CHIPID\n VALUE 0x0000\nROW 0x0040: CRIT\n VALUE 0x0000',
                       'VALUE 0x0000']:
            with patch.object(firmware, 'run', return_value=output):
                with self.assertRaisesRegex(firmware.FirmwareError, 'Could not read OTP row'):
                    otp.read(0x40)

    def test_picotool_option_works_on_either_side_of_command(self):
        for arguments in [['--picotool', 'custom.exe', 'info'], ['info', '--picotool', 'custom.exe']]:
            self.assertEqual(firmware.parser().parse_args(arguments).picotool, 'custom.exe')


if __name__ == '__main__':
    unittest.main()
