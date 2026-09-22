# SPDX-License-Identifier: AGPL-3.0-only
"""PicoForge v0.9.0 wire requests against the real C handlers, without a board."""
import datetime
import hashlib
import hmac
import json
import os
import subprocess
import unittest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import NameOID
from fido2 import cbor


@unittest.skipUnless(os.getenv('ATTESTATION_TEST_COMMAND'), 'Set ATTESTATION_TEST_COMMAND to the C test executable')
class OrgAttestationTest(unittest.TestCase):
    def setUp(self):
        self.proc = subprocess.Popen(json.loads(os.environ['ATTESTATION_TEST_COMMAND']),
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.scalar = self.key.private_numbers().private_value.to_bytes(32, 'big')
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Local protocol test')])
        now = datetime.datetime.now(datetime.timezone.utc)
        self.cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                     .public_key(self.key.public_key()).serial_number(1)
                     .not_valid_before(now - datetime.timedelta(days=1))
                     .not_valid_after(now + datetime.timedelta(days=1))
                     .sign(self.key, hashes.SHA256()).public_bytes(serialization.Encoding.DER))

    def tearDown(self):
        self.proc.stdin.close()
        self.proc.wait(timeout=15)
        self.proc.stdout.close()
        self.assertEqual(self.proc.returncode, 0)

    def line(self, text):
        self.proc.stdin.write(text + '\n'); self.proc.stdin.flush()
        result = self.proc.stdout.readline().strip()
        self.assertTrue(result, 'C handler exited before replying')
        return result

    def command(self, payload, opcode=0x41):
        result = self.line((bytes([opcode]) + cbor.encode(payload)).hex()).split(' ', 1)
        return int(result[0]), cbor.decode(bytes.fromhex(result[1])) if len(result) > 1 else None

    def mse(self):
        ephemeral = ec.generate_private_key(ec.SECP256R1())
        point = ephemeral.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        status, result = self.command({1: 1, 2: {1: {1: 2, 3: -25, -1: 1, -2: point[1:33], -3: point[33:]}}})
        self.assertEqual(status, 0)
        peer = b'\x04' + result[1][-2] + result[1][-3]
        secret = ephemeral.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer))
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=b'', info=peer).derive(secret)
        nonce = os.urandom(12)
        return nonce + ChaCha20Poly1305(key).encrypt(nonce, self.scalar, peer)

    def request(self, cmd, params=None, protocol=None):
        request = {1: cmd}
        if params is not None:
            request[2] = params
        if protocol is not None:
            auth = b'\xff' * 32 + bytes([0x41, cmd]) + (cbor.encode(params) if params is not None else b'')
            request[3] = protocol
            request[4] = hmac.digest(b'\x42' * 32, auth, 'sha256')[:16 if protocol == 1 else 32]
        return request

    def install(self, protocol=None):
        blob = self.mse()
        self.assertEqual(self.command(self.request(9, {1: blob, 2: self.cert}, protocol))[0], 0)

    def test_import_query_clear_without_enabling_enterprise(self):
        self.assertEqual(self.command({1: 11}), (0, {1: False}))
        self.install()
        status, value = self.command({1: 11})
        self.assertEqual(status, 0)
        self.assertTrue(value[1])
        self.assertEqual(value[2], hashlib.sha256(b'\x01' + len(self.cert).to_bytes(2, 'little') + self.cert).digest())
        status, key = self.line('key').split()
        self.assertEqual(int(status), 0)
        self.assertEqual(bytes.fromhex(key), self.scalar)
        status, chain = self.line('chain').split()
        self.assertEqual(int(status), 0)
        self.assertEqual(cbor.decode(bytes.fromhex(chain)), [self.cert])
        self.mse()
        self.assertEqual(self.command({1: 10})[0], 0)
        self.assertEqual(self.command({1: 11}), (0, {1: False}))

    def test_pin_authorization_and_touch(self):
        self.line('pin 1')
        blob = self.mse()
        self.assertEqual(self.command(self.request(9, {1: blob, 2: self.cert}))[0], 0x33)
        for protocol in (1, 2):
            self.install(protocol)
            self.mse()
            self.line('touch 1')
            self.assertEqual(self.command(self.request(10, protocol=protocol))[0], 0x2f)
            self.line('touch 0')
            self.assertTrue(self.command({1: 11})[1][1])
            self.mse()
            self.assertEqual(self.command(self.request(10, protocol=protocol))[0], 0)
        blob = self.mse()
        req = self.request(9, {1: blob, 2: self.cert}, 1)
        req[4] = b'\0' * 16
        self.assertEqual(self.command(req)[0], 0x33)
        blob = self.mse(); self.line('permission 4')
        self.assertEqual(self.command(self.request(9, {1: blob, 2: self.cert}, 1))[0], 0x33)
        self.assertEqual(self.command({1: 11}), (0, {1: False}))

    def test_one_use_expiration_and_channel_binding(self):
        blob = self.mse()
        req = {1: 9, 2: {1: blob, 2: self.cert}}
        self.assertEqual(self.command(req)[0], 0)
        self.assertEqual(self.command(req)[0], 0x30)
        for control in ('cid 8', 'expire'):
            self.line('cid 7'); blob = self.mse(); self.line(control)
            self.assertEqual(self.command({1: 9, 2: {1: blob, 2: self.cert}})[0], 0x30)

    def test_invalid_import_preserves_existing_identity(self):
        self.install()
        for variant in ('ciphertext', 'certificate', 'mismatch', 'write'):
            blob = self.mse(); cert = self.cert
            if variant == 'ciphertext':
                blob = blob[:-1] + bytes([blob[-1] ^ 1])
            elif variant == 'certificate':
                cert += b'\0'
            elif variant == 'mismatch':
                old = self.scalar; self.scalar = (1).to_bytes(32, 'big'); blob = self.mse(); self.scalar = old
            else:
                self.line('fail 1')
            self.assertNotEqual(self.command({1: 9, 2: {1: blob, 2: cert}})[0], 0)
            self.line('fail 0')
            self.assertTrue(self.command({1: 11})[1][1])
            self.assertEqual(bytes.fromhex(self.line('key').split()[1]), self.scalar)

    def test_chain_and_storage_integrity(self):
        # Two well-formed certs ensure x5c contains separate DER byte strings.
        blob = self.mse(); chain = self.cert * 2
        self.assertEqual(self.command({1: 9, 2: {1: blob, 2: chain}})[0], 0)
        self.assertEqual(cbor.decode(bytes.fromhex(self.line('chain').split()[1])), [self.cert, self.cert])
        self.line('corrupt')
        self.assertNotEqual(self.command({1: 11})[0], 0)
        result = self.line('key').split()
        self.assertNotEqual(int(result[0]), 0)
        self.assertEqual(bytes.fromhex(result[1]), b'\0' * 32)
        self.mse()
        self.assertEqual(self.command({1: 10})[0], 0)

    def test_legacy_routing_and_reset(self):
        self.assertEqual(self.command({1: 1})[0], 0x7e)
        self.assertEqual(self.command({1: 1}, opcode=0x0a)[0], 0x7e)
        for subcommand in (2, 3, 4, 5, 6):
            self.assertEqual(self.command({1: subcommand})[0], 0x7e)
        self.assertEqual(self.command({1: 7, 2: {2: b"credential", 3: {"id": b"user"}}})[0], 0x7e)
        self.install(); self.mse()
        self.assertEqual(self.line('07'), '0')
        self.assertEqual(self.command({1: 11}), (0, {1: False}))
        self.assertEqual(self.command({1: 10})[0], 0x30)

    def test_signed_audit_snapshot_uses_one_confirmation(self):
        self.assertEqual(self.command({1: 14, 2: {1: 2}}), (0, {1: False, 2: True}))
        self.assertEqual(self.command({1: 14, 2: {1: 1}})[0], 0)
        for protocol in (None, 1, 2):
            self.line('pin %d' % (protocol is not None))
            before = int(self.line('counters').split()[1])
            challenge = os.urandom(16)
            request = self.request(8, {1: challenge, 2: True}, protocol)
            status, result = self.command(request)
            self.assertEqual(status, 0)
            self.assertEqual(int(self.line('counters').split()[1]) - before, 1)
            log, checkpoint = result[1], result[2]
            head = log[3]
            self.assertEqual(len(log[4]), (log[2] - log[1]) * 20)
            for offset in range(0, len(log[4]), 20):
                head = hashlib.sha256(head + log[4][offset:offset + 20]).digest()
            self.assertEqual(head, checkpoint[1])
            self.assertEqual(log[2], checkpoint[2])
            key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), checkpoint[4])
            key.verify(checkpoint[3], b'RSK-AUDIT-CKPT-v1' + head + checkpoint[2].to_bytes(4, 'little') + challenge, ec.ECDSA(hashes.SHA256()))
        self.line('pin 1')
        before = self.line('counters')
        self.assertEqual(self.command({1: 8, 2: {1: challenge, 2: True}})[0], 0x36)
        self.assertEqual(self.line('counters'), before)
        self.line('touch 1')
        self.assertEqual(self.command(self.request(8, {1: challenge, 2: True}, 2))[0], 0x2f)
        self.line('touch 0')
        before = self.line('counters')
        self.assertEqual(self.command(self.request(8, {1: challenge, 2: 'invalid'}, 2))[0], 2)
        self.assertEqual(self.line('counters'), before)

    def test_parse_errors_do_not_write(self):
        before = self.line('counters').split()[0]
        for raw in ('41a201090109', '41a1010b00', '41a2010902a0', '41a2010a02a0'):
            self.assertNotEqual(int(self.line(raw).split()[0]), 0)
        self.assertEqual(self.line('counters').split()[0], before)


if __name__ == '__main__':
    unittest.main()
