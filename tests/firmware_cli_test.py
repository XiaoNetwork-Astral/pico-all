"""CLI routing and help tests. No keys, USB access or picotool execution."""
import contextlib
import io
import unittest
from unittest.mock import patch
import firmware


class CliTest(unittest.TestCase):
    def invoke(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = firmware.main(argv)
            except SystemExit as exit:
                code = exit.code
        return code, out.getvalue(), err.getvalue()

    def test_no_arguments_and_group_help_do_not_find_tools_or_open_menu(self):
        with patch.object(firmware, 'tool_path') as tools, patch.object(firmware, 'menu') as menu:
            for argv in [[], ['security']]:
                code, out, err = self.invoke(argv)
                self.assertEqual(code, 0)
                self.assertIn('Commands' if not argv else 'Security commands', out)
                self.assertFalse(err)
            tools.assert_not_called()
            menu.assert_not_called()

    def test_short_and_long_help_work_at_every_level(self):
        for path in [[], ['sign'], ['security'], ['security', 'enable']]:
            with patch.object(firmware, 'tool_path') as tools:
                short = self.invoke([*path, '-h'])
                long = self.invoke([*path, '--help'])
                self.assertEqual(short[0], 0)
                self.assertEqual(long[0], 0)
                self.assertNotIn('Examples:', short[1])
                self.assertIn('Examples:', long[1])
                tools.assert_not_called()
        self.assertIn('Permanently require signed firmware', long[1])

    def test_global_tool_option_is_preserved_at_each_depth(self):
        for argv in [
            ['--picotool', 'tool', 'security', 'status', '-s', 'id'],
            ['security', '--picotool', 'tool', 'status', '-s', 'id'],
            ['security', 'status', '--picotool', 'tool', '-s', 'id'],
        ]:
            args = firmware.parser().parse_args(argv)
            self.assertEqual(args.picotool, 'tool')
            self.assertEqual(args.serial, 'id')
        args = firmware.parser().parse_args(['security', '-s', 'id', 'enable', 'signed.uf2'])
        self.assertEqual(args.serial, 'id')
        self.assertEqual(args.selected_parser.prog, 'firmware.py security enable')

    def test_rejects_irrelevant_missing_and_abbreviated_parameters_before_io(self):
        invalid = [
            ['security', 'status', '--apply', '-s', 'id'],
            ['security', 'prove', 'signed.uf2', '--apply', '-s', 'id'],
            ['security', 'enable', 'signed.uf2', '--slot', '1', '-s', 'id'],
            ['security', 'enable', 'signed.uf2', '--yes', '-s', 'id'],
            ['security', 'enable', 'signed.uf2', '--app', '-s', 'id'],
            ['security', 'enable', '-s', 'id'],
            ['security', 'enable', 'signed.uf2'],
            ['security', 'status', '--firmware', 'signed.uf2', '-s', 'id'],
            ['--pico', 'tool', 'info'],
        ]
        with patch.object(firmware, 'tool_path') as tools, patch.object(firmware, 'security') as security:
            for argv in invalid:
                with self.subTest(argv=argv):
                    code, out, err = self.invoke(argv)
                    self.assertEqual(code, 2)
                    self.assertFalse(out)
                    self.assertIn('--help', err)
            tools.assert_not_called()
            security.assert_not_called()

    def test_new_security_syntax_routes_preview_and_apply_separately(self):
        with patch.object(firmware, 'tool_path', return_value='tool'), patch.object(firmware, 'security') as operation:
            for apply in [False, True]:
                argv = ['security', 'load-key', 'signed file.uf2', '-s', 'id', '--slot', '2']
                if apply:
                    argv.append('--apply')
                self.assertEqual(self.invoke(argv)[0], 0)
                operation.assert_called_with('tool', 'load-key', 'id', 'signed file.uf2', 2, apply)
            self.assertEqual(self.invoke(['security', 'status', '-s', 'id'])[0], 0)
            operation.assert_called_with('tool', 'status', 'id', None, 0, False)

    def test_prepare_needs_no_picotool_and_keeps_confirmation_flag(self):
        with patch.object(firmware, 'tool_path') as tools, patch.object(firmware, 'prepare_storage') as prepare:
            self.assertEqual(self.invoke(['security', 'prepare', '-s', 'id'])[0], 0)
            prepare.assert_called_with('id', False)
            self.assertEqual(self.invoke(['security', 'prepare', '-s', 'id', '--apply'])[0], 0)
            prepare.assert_called_with('id', True)
            tools.assert_not_called()

    def test_menu_is_explicit_and_requires_a_terminal(self):
        with patch.object(firmware.sys.stdin, 'isatty', return_value=False), patch.object(firmware, 'tool_path') as tools:
            code, out, err = self.invoke(['menu'])
            self.assertEqual(code, 2)
            self.assertIn('interactive terminal', err)
            tools.assert_not_called()
        with patch.object(firmware.sys.stdin, 'isatty', return_value=True), \
             patch.object(firmware, 'tool_path', return_value='tool'), patch.object(firmware, 'menu') as menu:
            self.assertEqual(self.invoke(['menu'])[0], 0)
            menu.assert_called_once_with('tool')

    def test_sign_short_options_route_to_existing_implementation(self):
        with patch.object(firmware, 'tool_path', return_value='tool'), patch.object(firmware, 'sign') as sign:
            self.assertEqual(self.invoke(['sign', 'input.uf2', '-k', 'key.pem', '-o', 'out.uf2', '--new-key', '-y'])[0], 0)
            sign.assert_called_once_with('tool', 'input.uf2', 'key.pem', 'out.uf2', True, True)


if __name__ == '__main__':
    unittest.main()
