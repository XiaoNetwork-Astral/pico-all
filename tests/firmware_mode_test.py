"""Mode transitions through mocked PC/SC and picotool; never accesses USB."""
import io
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
from rich.console import Console
from smartcard.Exceptions import CardConnectionException, SmartcardException
import firmware

SERIAL = '00112233445566AA'
OTHER = '11223344556677BB'
ABSENT = 'No accessible RP-series devices in BOOTSEL mode were found.'
INFO = f'Device Information\n type: RP2350\n chipid: 0x{SERIAL.lower()}\n'


class ModeTest(unittest.TestCase):
    def setUp(self):
        self.capture = io.StringIO()
        console = patch.object(firmware, 'console', Console(file=self.capture))
        console.start()
        self.addCleanup(console.stop)
        # Any missing transport mock must fail before touching a real device.
        for target in ['firmware.subprocess.run', 'smartcard.System.readers']:
            blocker = patch(target, side_effect=AssertionError('Unexpected hardware access'))
            blocker.start()
            self.addCleanup(blocker.stop)

    def test_probe_parses_actual_picotool_format_and_plain_absence(self):
        for output, expected in [(INFO, [SERIAL]), (firmware.PicotoolError(ABSENT), []),
                                 (firmware.PicotoolError(ABSENT[:-1] + f' with serial\n number {SERIAL}.'), [])]:
            with patch.object(firmware, 'run', side_effect=output if isinstance(output, Exception) else None,
                              return_value=output) as backend:
                self.assertEqual(firmware.bootsel_boards('tool', SERIAL), expected)
                self.assertEqual(backend.call_args.args[1], ['info', '-d', '--ser', SERIAL])

    def test_driver_error_malformed_result_and_wrong_serial_never_switch(self):
        errors = [firmware.PicotoolError(ABSENT + '\nbut: device inaccessible; install driver'),
                  firmware.FirmwareError('USB timed out'), 'type: RP2350\n',
                  INFO.replace(SERIAL.lower(), OTHER.lower())]
        for result in errors:
            with self.subTest(result=result), patch.object(firmware, 'run',
                    side_effect=result if isinstance(result, Exception) else None, return_value=result), \
                    patch.object(firmware, 'management') as apdu:
                with self.assertRaises(firmware.FirmwareError):
                    firmware.ensure_bootsel('tool', SERIAL)
                apdu.assert_not_called()

    def test_already_bootsel_skips_button_and_pcsc(self):
        with patch.object(firmware, 'run', return_value=INFO), \
             patch.object(firmware, 'management') as apdu:
            self.assertEqual(firmware.ensure_bootsel('tool', SERIAL.lower()), SERIAL)
            apdu.assert_not_called()

    def test_automatic_transition_waits_for_selected_serial(self):
        with patch.object(firmware, 'bootsel_boards', side_effect=[[], [], [SERIAL]]) as boot, \
             patch.object(firmware, 'normal_boards', return_value=[SERIAL]), \
             patch.object(firmware, 'management') as apdu, patch.object(firmware.time, 'sleep'):
            self.assertEqual(firmware.ensure_bootsel('tool', None), SERIAL)
            apdu.assert_called_once_with(SERIAL, [0x80, 0x1f, 1, 0, 0])
            self.assertEqual([call.args for call in boot.call_args_list],
                             [('tool', None), ('tool', SERIAL), ('tool', SERIAL)])
            self.assertIn('yellow', self.capture.getvalue())

    def test_multiple_or_missing_boards_do_not_send_commands(self):
        for boot, normal in [([SERIAL], [OTHER]), ([], [SERIAL, OTHER]),
                             ([SERIAL, OTHER], []), ([], []), ([], [SERIAL, SERIAL])]:
            with patch.object(firmware, 'bootsel_boards', return_value=boot), \
                 patch.object(firmware, 'normal_boards', return_value=normal), \
                 patch.object(firmware, 'management') as apdu:
                with self.assertRaises(firmware.FirmwareError):
                    firmware.ensure_bootsel('tool', None)
                apdu.assert_not_called()

    def test_button_denial_stops_flash_even_with_yes(self):
        with patch.object(firmware, 'uf2_file', return_value=Path('signed.uf2')), \
             patch.object(firmware, 'run') as backend, \
             patch.object(firmware, 'detect_board', return_value=(SERIAL, 'normal')), \
             patch.object(firmware, 'management', side_effect=firmware.FirmwareError('6985')), \
             patch.object(firmware, 'wait_for_mode') as wait:
            with self.assertRaisesRegex(firmware.FirmwareError, '6985'):
                firmware.flash('tool', 'signed.uf2', SERIAL, yes=True)
            self.assertEqual(backend.call_count, 1)  # Only the local UF2 was inspected.
            self.assertEqual(backend.call_args.args[1], ['info', '-b', 'signed.uf2'])
            wait.assert_not_called()

    def test_wrong_board_cannot_satisfy_reconnect_wait(self):
        with patch.object(firmware, 'normal_boards', return_value=[OTHER]), \
             patch.object(firmware.time, 'monotonic', side_effect=[0, 0, 31]), \
             patch.object(firmware.time, 'sleep'):
            with self.assertRaisesRegex(firmware.FirmwareError, 'did not appear'):
                firmware.wait_for_mode('tool', SERIAL, 'normal')

    def test_transition_timeout_prevents_flash(self):
        with patch.object(firmware, 'uf2_file', return_value=Path('signed.uf2')), \
             patch.object(firmware, 'run') as backend, \
             patch.object(firmware, 'detect_board', return_value=(SERIAL, 'normal')), \
             patch.object(firmware, 'management'), \
             patch.object(firmware, 'bootsel_boards', return_value=[]), \
             patch.object(firmware.time, 'monotonic', side_effect=[0, 31]):
            with self.assertRaisesRegex(firmware.FirmwareError, 'did not appear'):
                firmware.flash('tool', 'signed.uf2', SERIAL, yes=True)
            self.assertEqual(backend.call_count, 1)

    def test_flash_uses_discovered_serial_after_confirmation(self):
        events = []
        with patch.object(firmware, 'uf2_file', return_value=Path('signed.uf2')), \
             patch.object(firmware, 'run') as backend, \
             patch.object(firmware, 'approved', side_effect=lambda *a: events.append('consent')), \
             patch.object(firmware, 'ensure_bootsel', side_effect=lambda *a: events.append('switch') or SERIAL):
            firmware.flash('tool', 'signed.uf2', None)
            self.assertEqual(events, ['consent', 'switch'])
            self.assertEqual(backend.call_args.args[1], ['load', '-v', '-x', 'signed.uf2', '--ser', SERIAL])

    def test_info_and_all_bootsel_security_stages_use_transition(self):
        with patch.object(firmware, 'ensure_bootsel', return_value=SERIAL) as switch, \
             patch.object(firmware, 'run', return_value=INFO) as backend:
            firmware.board_info('tool', None)
            switch.assert_called_once_with('tool', None)
            self.assertEqual(backend.call_args.args[1][-2:], ['--ser', SERIAL])
        for stage in ['status', 'load-key', 'harden', 'enable', 'lock']:
            with patch.object(firmware, 'ensure_bootsel', side_effect=firmware.FirmwareError('stop here')) as switch, \
                 patch.object(firmware.BootOtp, 'board') as board:
                with self.assertRaisesRegex(firmware.FirmwareError, 'stop here'):
                    firmware.security('tool', stage, SERIAL, 'signed.uf2', apply=True)
                switch.assert_called_once_with('tool', SERIAL)
                board.assert_not_called()

    def test_idle_bootsel_reboot_only_reboots_and_checks_normal_mode(self):
        with patch.object(firmware, 'detect_board', return_value=(SERIAL, 'bootsel')), \
             patch.object(firmware, 'run') as backend, \
             patch.object(firmware, 'wait_for_mode') as wait, \
             patch.object(firmware, 'management') as apdu:
            firmware.device_mode('tool', 'reboot', None)
            backend.assert_called_once_with('tool', ['reboot', '-a', '--ser', SERIAL], 'Starting firmware...', 30)
            wait.assert_called_once_with('tool', SERIAL, 'normal')
            apdu.assert_not_called()

    def test_normal_reboot_and_failed_reconnect_reporting(self):
        with patch.object(firmware, 'detect_board', return_value=(SERIAL, 'normal')), \
             patch.object(firmware, 'management') as apdu, patch.object(firmware.time, 'sleep'), \
             patch.object(firmware, 'wait_for_mode', side_effect=firmware.FirmwareError('not running')):
            with self.assertRaisesRegex(firmware.FirmwareError, 'not running'):
                firmware.device_mode('tool', 'reboot', SERIAL)
            apdu.assert_called_once_with(SERIAL, [0x80, 0x1f, 0, 0, 0])
            self.assertNotIn('is running', self.capture.getvalue())

    def test_management_selects_by_serial_and_closes_connections(self):
        readers = []
        connections = []
        for serial in [OTHER, SERIAL]:
            reader = MagicMock()
            reader.__str__.return_value = 'Pico All CCID'
            connection = reader.createConnection.return_value
            connection.transmit.side_effect = [([0, 0, 1, 0, *bytes.fromhex(serial)], 0x90, 0), ([], 0x90, 0)]
            readers.append(reader)
            connections.append(connection)
        with patch('smartcard.System.readers', return_value=readers):
            firmware.management(SERIAL, [0x80, 0x1f, 1, 0, 0])
        self.assertEqual(connections[0].transmit.call_count, 1)
        self.assertEqual(connections[1].transmit.call_count, 2)
        for connection in connections:
            connection.disconnect.assert_called_once()

    def test_management_disconnect_only_tolerated_for_reboot(self):
        for command, succeeds in [([0x80, 0x1f, 1, 0, 0], True), ([0x80, 0x1f, 0, 0, 0], True),
                                  ([0x80, 0x1d, 0, 2, 0], False)]:
            reader = MagicMock()
            reader.__str__.return_value = 'Pico All'
            connection = reader.createConnection.return_value
            connection.transmit.side_effect = [([0, 0, 1, 0, *bytes.fromhex(SERIAL)], 0x90, 0),
                                                CardConnectionException('removed')]
            connection.disconnect.side_effect = CardConnectionException('removed')
            with patch('smartcard.System.readers', return_value=[reader]):
                if succeeds:
                    self.assertEqual(firmware.management(SERIAL, command), b'')
                else:
                    with self.assertRaisesRegex(firmware.FirmwareError, 'PC/SC'):
                        firmware.management(SERIAL, command)

    def test_pcsc_service_restarts_are_only_retried_during_reconnect(self):
        with patch('smartcard.System.readers', side_effect=SmartcardException('service stopped', hresult=0x8010001e - 0x100000000)):
            self.assertEqual(firmware.normal_boards(waiting=True), [])
            with self.assertRaisesRegex(firmware.FirmwareError, 'PC/SC'):
                firmware.normal_boards()
        with patch('smartcard.System.readers', side_effect=SmartcardException('access denied', hresult=0x80100027 - 0x100000000)):
            with self.assertRaisesRegex(firmware.FirmwareError, 'PC/SC'):
                firmware.normal_boards(waiting=True)

    def test_management_button_rejection_is_not_reboot_acknowledgement(self):
        reader = MagicMock()
        reader.__str__.return_value = 'Pico All'
        connection = reader.createConnection.return_value
        connection.transmit.side_effect = [([0, 0, 1, 0, *bytes.fromhex(SERIAL)], 0x90, 0),
                                            ([], 0x69, 0x85)]
        with patch('smartcard.System.readers', return_value=[reader]):
            with self.assertRaisesRegex(firmware.FirmwareError, '6985'):
                firmware.management(SERIAL, [0x80, 0x1f, 1, 0, 0])
        connection.disconnect.assert_called_once()

    def test_interrupted_image_can_be_identified_without_image_metadata(self):
        identity = ''.join(f'ROW {i:#06x}: CHIPID\n VALUE {int(SERIAL[12-4*i:16-4*i],16):#06x}\n' for i in range(4))
        with patch.object(firmware, 'run', side_effect=[
                firmware.PicotoolError('ERROR: Block loop is not valid - no block found at 1009f7e4'), identity]) as backend:
            self.assertEqual(firmware.ensure_bootsel('tool', SERIAL), SERIAL)
            self.assertEqual(backend.call_args.args[1],
                ['otp', 'get', '-c', '1', '-e', '-n', '--ser', SERIAL, '0x0', '0x1', '0x2', '0x3'])
        for invalid in [identity.replace('0x66aa', '0x66ab'), identity + identity,
                        identity.replace('VALUE 0x66aa', 'VALUE 0x10000'), '']:
            with patch.object(firmware, 'run', return_value=invalid):
                with self.assertRaises(firmware.FirmwareError):
                    firmware.recovery_board('tool', SERIAL)

    def test_cli_mode_commands_and_tool_options(self):
        with patch.object(firmware, 'tool_path', return_value='tool'), \
             patch.object(firmware, 'device_mode') as operation:
            for action in ['bootsel', 'reboot']:
                self.assertEqual(firmware.main(['device', '-s', SERIAL, action, '--picotool', 'tool']), 0)
                operation.assert_called_with('tool', action, SERIAL)


if __name__ == '__main__':
    unittest.main()
