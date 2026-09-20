"""End-to-end management tests against the C OTP model; never accesses USB.
Set OTP_SIM_COMMAND to a JSON argv for the compiled otp_root_test executable.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch
from rich.console import Console
import firmware


class SecurityProtocolTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        command = os.environ.get('OTP_SIM_COMMAND')
        if not command:
            raise unittest.SkipTest('Set OTP_SIM_COMMAND to the otp_root_test executable argv')
        cls.process = subprocess.Popen([*json.loads(command), '--server'], stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, text=True, bufsize=1)

    @classmethod
    def tearDownClass(cls):
        cls.process.stdin.close()
        cls.process.wait(timeout=15)
        cls.process.stdout.close()

    def send(self, line):
        self.process.stdin.write(line + '\n')
        self.process.stdin.flush()
        reply = self.process.stdout.readline().strip()
        self.assertTrue(reply, 'OTP simulator stopped unexpectedly')
        return reply

    def command(self, line):
        code, data = self.send(line).split()
        return int(code), int(data, 16)

    def setUp(self):
        self.command('reset')
        self.capture = io.StringIO()
        self.patcher = patch.object(firmware, 'console', Console(file=self.capture))
        self.patcher.start()
        self.addCleanup(self.patcher.stop)
        self.calls = []
        self.transport = patch.object(firmware, 'run', side_effect=self.backend)
        self.transport.start()
        self.addCleanup(self.transport.stop)
        self.otp = firmware.BootOtp('simulator', '0011223344556677')
        self.fp = hashlib.sha256(b'local simulated signing public key').digest()

    def backend(self, tool, args, label, *extra, **kwargs):
        self.calls.append(args)
        self.assertEqual(tool, 'simulator')
        if args[:2] == ['info', '-d']:
            return 'type: RP2350\nsecure boot: 1\nchipid: 0011223344556677\n'
        self.assertEqual(args[0], 'otp')
        self.assertEqual(args[-2:], ['--ser', '0011223344556677'])
        ecc = '-e' in args
        if args[1] == 'get':
            row = int(args[6], 16)
            code, value = self.command(('ecc' if ecc else 'raw') + f' {row:x}')
            if code:
                raise firmware.FirmwareError('Simulated read or ECC failure')
            return f'ROW {row:#06x}: SIMULATED\n    VALUE {value:#08x}\n'
        self.assertEqual(args[1], 'set')
        row, value = int(args[5], 16), int(args[6], 16)
        code, _ = self.command(('setecc' if ecc else 'setraw') + f' {row:x} {value:x}')
        if code:
            raise firmware.FirmwareError('Simulated programming interruption or lock')
        return ''

    def apply(self, action, slot=0):
        state = firmware.boot_state(self.otp)
        plan = firmware.security_plan(self.otp, state, action, self.fp, slot)
        for row, value, ecc in plan:
            self.otp.write(row, value, ecc)
        return plan

    def test_full_protocol_flow_with_production_root_code(self):
        self.assertEqual(self.command('boot 1')[0], 0)
        self.apply('load-key')
        self.assertEqual(self.apply('load-key'), [])
        self.apply('harden')
        self.assertEqual(self.command('boot 1')[0], 0)
        self.apply('enable')
        self.assertEqual(self.command('boot 0')[0], -1)  # Legacy data refuses provisioning.
        self.assertEqual(self.command('boot 1')[0], 1)
        data = bytes.fromhex(self.send('apdu'))
        self.assertEqual(data, bytes.fromhex('010138000000759000'))
        # Host OTP interface cannot read the device-root page.
        with self.assertRaises(firmware.FirmwareError):
            self.otp.read(56 * 64)
        self.apply('lock')
        state = firmware.boot_state(self.otp)
        self.assertEqual(state['valid'], 1)
        self.assertEqual(state['revoked'], 14)
        self.assertEqual(state['locks'], [0x151515, 0x151515])
        self.assertEqual(self.apply('lock'), [])
        self.assertEqual(self.command('boot 0')[0], 1)
        with self.assertRaises(firmware.FirmwareError):
            self.otp.write(0x40, 0x77)

    def test_wrong_key_and_order_never_write(self):
        for stage in ['harden', 'enable', 'lock']:
            with self.assertRaises(firmware.FirmwareError):
                self.apply(stage)
        self.apply('load-key')
        with self.assertRaises(firmware.FirmwareError):
            self.apply('enable')
        self.fp = hashlib.sha256(b'wrong key').digest()
        with self.assertRaises(firmware.FirmwareError):
            self.apply('harden')
        state = firmware.boot_state(self.otp)
        self.assertEqual(state['crit'], 0)

    def test_key_valid_is_last_and_power_cut_does_not_enable_boot(self):
        plan = firmware.security_plan(self.otp, firmware.boot_state(self.otp), 'load-key', self.fp, 0)
        self.assertEqual([x[0] for x in plan[-3:]], list(firmware.FLAGS_ROWS))
        self.command('fault 5')
        with self.assertRaises(firmware.FirmwareError):
            for row, value, ecc in plan:
                self.otp.write(row, value, ecc)
        self.assertEqual(self.command('raw 4b')[1], 0)
        self.assertEqual(self.command('raw 40')[1], 0)

    def test_rbit8_uses_three_of_eight_not_first_copy(self):
        for row in [0x41, 0x44]:
            self.command(f'setraw {row:x} 1')
        self.assertEqual(firmware.boot_state(self.otp)['crit'], 0)
        self.command('setraw 47 1')
        self.assertEqual(firmware.boot_state(self.otp)['crit'], 1)

    def test_raw_transport_failure_is_not_blank(self):
        with patch.object(firmware, 'run', return_value='ACCESS DENIED'):
            with self.assertRaises(firmware.FirmwareError):
                self.otp.read(0x40)
        with self.assertRaises(firmware.FirmwareError):
            self.otp.write(0xe00, 1)

    def test_revoked_slot_rejected_even_with_one_copy(self):
        self.command('setraw 4c 100')
        with self.assertRaises(firmware.FirmwareError):
            self.apply('load-key')

    def test_preview_cannot_program(self):
        with patch.object(firmware, 'firmware_fingerprint', return_value=self.fp), \
             patch.object(firmware, 'uf2_file', return_value=Path('simulated.uf2')), \
             patch.object(Path, 'read_bytes', return_value=b'simulated firmware'):
            firmware.security('simulator', 'load-key', self.otp.serial, 'simulated.uf2')
        self.assertFalse(any(call[:2] == ['otp', 'set'] for call in self.calls))
        self.assertIn('Preview only', self.capture.getvalue())

    def test_torn_boot_key_can_use_a_different_slot(self):
        self.command('fault 5')
        with self.assertRaises(firmware.FirmwareError):
            self.apply('load-key')
        self.command('fault ffffffff')
        self.assertIsNone(firmware.boot_state(self.otp)['fps'][0])
        self.apply('load-key', 1)
        self.apply('harden')
        self.apply('enable')
        self.assertEqual(self.command('boot 1')[0], 1)
        self.apply('lock')
        self.assertEqual(firmware.boot_state(self.otp)['revoked'], 13)

    def test_torn_final_lock_is_resumable_after_permissions_latch(self):
        self.apply('load-key'); self.apply('harden'); self.apply('enable')
        self.assertEqual(self.command('boot 1')[0], 1)
        self.command('fault 3')  # Revocation copies complete, page1 lock torn.
        with self.assertRaises(firmware.FirmwareError):
            self.apply('lock')
        self.command('fault ffffffff')
        self.assertEqual(self.command('boot 0')[0], 1)
        self.apply('lock')
        state = firmware.boot_state(self.otp)
        self.assertEqual(state['locks'], [0x1515, 0x151515])
        self.assertEqual(self.apply('lock'), [])

    def test_prepare_preview_and_protected_board_cannot_erase(self):
        with patch.object(firmware, 'management', return_value=bytes.fromhex('0100ff00000000')) as api:
            firmware.prepare_storage(self.otp.serial, False)
            self.assertEqual(api.call_count, 1)
            self.assertEqual(api.call_args.args[1], [0x80, 0x1e, 6, 0, 0])
        with patch.object(firmware, 'management', return_value=bytes.fromhex('01013800000075')) as api:
            with self.assertRaises(firmware.FirmwareError):
                firmware.prepare_storage(self.otp.serial, True)
            self.assertEqual(api.call_count, 1)

    def test_prepare_requires_typed_confirmation_and_physical_command(self):
        with patch.object(firmware, 'management', return_value=bytes.fromhex('0100ff00000000')) as api, \
             patch.object(firmware.sys.stdin, 'isatty', return_value=True), \
             patch.object(firmware.Prompt, 'ask', return_value='wrong'):
            with self.assertRaises(firmware.FirmwareError):
                firmware.prepare_storage(self.otp.serial, True)
            self.assertEqual(api.call_count, 1)
        with patch.object(firmware, 'management', return_value=bytes.fromhex('0100ff00000000')) as api, \
             patch.object(firmware.sys.stdin, 'isatty', return_value=True), \
             patch.object(firmware.Prompt, 'ask', return_value='ERASE ' + self.otp.serial):
            firmware.prepare_storage(self.otp.serial, True)
            self.assertEqual(api.call_args.args[1], [0x80, 0x1d, 0, 2, 0])

    def test_fingerprint_matches_verified_metadata_and_rejects_ambiguity(self):
        key = bytes(range(64))
        metadata = "Metadata Block 1\n target chip: RP2350\n image type: ARM Secure\n signature: verified\n public key: " + key.hex()
        with patch.object(firmware, 'run', return_value=metadata):
            self.assertEqual(firmware.firmware_fingerprint('simulator', Path('test.uf2')), hashlib.sha256(key).digest())
        for invalid in [metadata.replace('verified', 'failed'), metadata + "\nMetadata Block 2\n" + metadata.split('\n', 1)[1]]:
            with patch.object(firmware, 'run', return_value=invalid):
                with self.assertRaises(firmware.FirmwareError):
                    firmware.firmware_fingerprint('simulator', Path('test.uf2'))

    def test_storage_check_rejects_existing_data_and_truncated_reads(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory, patch.object(firmware, 'ROOT', Path(directory)):
            for contents, good in [(b'\xff' * 4096, True), (b'\xff' * 4095 + b'X', False), (b'\xff', False)]:
                def backend(tool, args, *unused):
                    if args[0] == 'info':
                        return 'partition 1 (A ob/ 0): 003fd000->00400000'
                    self.assertEqual(args[:2], ['save', '-r'])
                    Path(args[4]).write_bytes(contents)
                    return ''
                with patch.object(firmware, 'run', side_effect=backend):
                    if good:
                        firmware.require_empty_storage('simulator', self.otp.serial, Path('test.uf2'))
                    else:
                        with self.assertRaises(firmware.FirmwareError):
                            firmware.require_empty_storage('simulator', self.otp.serial, Path('test.uf2'))
                self.assertFalse(list((Path(directory)/'.private').glob('storage-check-*')))


if __name__ == '__main__':
    unittest.main()

