# Copyright 2019 The NATS Authors
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import unittest
import sys
import nkeys
import binascii
import base64
import ed25519

class NatsTestCase(unittest.TestCase):

    def setUp(self):
        print("\n=== RUN {0}.{1}".format(
            self.__class__.__name__, self._testMethodName))

class NkeysTest(NatsTestCase):

    def test_from_seed_keypair(self):
        seed = "SUAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU"
        kp = nkeys.from_seed(bytearray(seed.encode()))
        self.assertTrue(type(kp) is nkeys.KeyPair)

    def test_keypair_sign_nonce(self):
        seed = "SUAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU"
        kp = nkeys.from_seed(bytearray(seed.encode()))
        raw = kp.sign(b"PXoWU7zWAMt75FY")
        sig = base64.b64encode(raw)
        self.assertEqual(sig, b'ZaAiVDgB5CeYoXoQ7cBCmq+ZllzUnGUoDVb8C7PilWvCs8XKfUchAUhz2P4BYAF++Dg3w05CqyQFRDiGL6LrDw==')

    def test_from_seed_keypair_bad_padding(self):
        with self.assertRaises(binascii.Error):
            seed = "UAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU"
            nkeys.from_seed(bytearray(seed.encode()))

    def test_from_seed_keypair_invalid_seed(self):
        with self.assertRaises(nkeys.ErrInvalidSeed):
            seed = "AUAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU"
            nkeys.from_seed(bytearray(seed.encode()))

    def test_from_seed_keypair_valid_prefix_byte(self):
        seeds = [
            "SNAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU",
            "SCAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU",
            "SOAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU",
            "SUAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU"
            ]
        for seed in seeds:
            nkeys.from_seed(bytearray(seed.encode()))

    def test_from_seed_keypair_invalid_public_prefix_byte(self):
        seeds = [
            b'SBAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU',
            b'SDAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU',
            b'PWAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU',
            b'PMAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU'
            ]
        with self.assertRaises(nkeys.ErrInvalidPrefixByte):
            for seed in seeds:
                nkeys.from_seed(bytearray(seed))

    def test_keypair_wipe(self):
        seed = "SUAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU"
        kp = nkeys.from_seed(bytearray(seed.encode()))
        self.assertTrue(kp._keys is not None)

        kp.wipe()
        with self.assertRaises(AttributeError):
            kp._keys
        with self.assertRaises(AttributeError):
            kp._seed

    def test_keypair_public_key(self):
        seed = "SUAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU"
        encoded_seed = bytearray(seed.encode())
        kp = nkeys.from_seed(encoded_seed)

        self.assertEqual(None, kp._public_key)
        self.assertEqual("UCK5N7N66OBOINFXAYC2ACJQYFSOD4VYNU6APEJTAVFZB2SVHLKGEW7L", kp.public_key)

        # Confirm that the public key is wiped as well.
        kp.wipe()
        with self.assertRaises(AttributeError):
            kp._public_key

    def test_keypair_use_seed_to_verify_signature(self):
        seed = "SUAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU"
        encoded_seed = bytearray(seed.encode())
        kp = nkeys.from_seed(encoded_seed)
        nonce = b'NcMQZSlX2lZ3Y4w'
        sig = kp.sign(nonce)
        kp.verify(sig, nonce)

        with self.assertRaises(ed25519.BadSignatureError):
            kp.verify(sig, nonce+b'asdf')

if __name__ == '__main__':
    runner = unittest.TextTestRunner(stream=sys.stdout)
    unittest.main(verbosity=2, exit=False, testRunner=runner)
