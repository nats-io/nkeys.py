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
import os

PREFIXES = [
    nkeys.PREFIX_BYTE_OPERATOR, nkeys.PREFIX_BYTE_SERVER,
    nkeys.PREFIX_BYTE_CLUSTER, nkeys.PREFIX_BYTE_ACCOUNT,
    nkeys.PREFIX_BYTE_USER
]


class NatsTestCase(unittest.TestCase):

    def setUp(self):
        print(
            "\n=== RUN {0}.{1}".format(
                self.__class__.__name__, self._testMethodName
            )
        )


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
        self.assertEqual(
            sig,
            b'ZaAiVDgB5CeYoXoQ7cBCmq+ZllzUnGUoDVb8C7PilWvCs8XKfUchAUhz2P4BYAF++Dg3w05CqyQFRDiGL6LrDw=='
        )

    def test_from_seed_keypair_bad_padding(self):
        with self.assertRaises(nkeys.InvalidSeedError):
            seed = "UAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU"
            nkeys.from_seed(bytearray(seed.encode()))

    def test_from_seed_keypair_invalid_seed(self):
        with self.assertRaises(nkeys.InvalidSeedError):
            seed = "AUAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU"
            nkeys.from_seed(bytearray(seed.encode()))

        with self.assertRaises(nkeys.InvalidSeedError):
            seed = ""
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
        with self.assertRaises(nkeys.InvalidPrefixByteError):
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
        self.assertEqual(
            "UCK5N7N66OBOINFXAYC2ACJQYFSOD4VYNU6APEJTAVFZB2SVHLKGEW7L",
            kp.public_key
        )

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
        self.assertTrue(kp.verify(nonce, sig))
        with self.assertRaises(nkeys.InvalidSignatureError):
            kp.verify(nonce + b'asdf', sig)

    def test_keypair_seed_property(self):
        seed = bytearray(
            b"SUAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU"
        )
        kp = nkeys.from_seed(seed)
        self.assertEqual(
            kp.seed,
            bytearray(
                b"SUAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU"
            )
        )

        # Throw away the seed.
        kp.wipe()

        with self.assertRaises(nkeys.InvalidSeedError):
            kp.seed

    def test_keypair_public_key(self):
        seed = "SUAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU"
        encoded_seed = bytearray(seed.encode())
        kp = nkeys.from_seed(encoded_seed)

        self.assertEqual(None, kp._public_key)
        self.assertEqual(
            b"UCK5N7N66OBOINFXAYC2ACJQYFSOD4VYNU6APEJTAVFZB2SVHLKGEW7L",
            kp.public_key
        )

        # Confirm that the public key is wiped as well.
        kp.wipe()
        with self.assertRaises(AttributeError):
            kp._public_key

    def test_keypair_private_key(self):
        seed = "SUAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU"
        encoded_seed = bytearray(seed.encode())
        kp = nkeys.from_seed(encoded_seed)
        self.assertEqual(None, kp._public_key)

        priv = kp.private_key
        self.assertEqual(
            b"PDC2WWLK67NUTFW7ZH5A7FOPZC32VXYZYWYNQMQ6RQWP2FEEF6KDVFOW7W7PHAXEGS3QMBNABEYMCZHB6K4G2PAHSEZQKS4Q5JKTVVDCJORA",
            priv
        )

        # Confirm that the private_key is wiped as well.
        kp.wipe()
        with self.assertRaises(AttributeError):
            kp._keys
        with self.assertRaises(AttributeError):
            kp._private_key

    def test_roundtrip_seed_encoding(self):
        # This test is a low-tech property test in disguise,
        # testing the property:
        #   decode . encode == identity
        # Using a proper framework like hypothesis might be preferable.
        num_trials = 500
        raw_seeds = [os.urandom(32) for _ in range(num_trials)]
        for raw_seed in raw_seeds:
            for prefix in PREFIXES:
                with self.subTest(rawseed=raw_seed, prefix=prefix):
                    encoded_seed = nkeys.encode_seed(raw_seed, prefix)
                    decoded_prefix, decoded_seed = nkeys.decode_seed(
                        encoded_seed
                    )
                    self.assertEqual(prefix, decoded_prefix)
                    self.assertEqual(raw_seed, decoded_seed)


if __name__ == '__main__':
    runner = unittest.TextTestRunner(stream=sys.stdout)
    unittest.main(verbosity=2, exit=False, testRunner=runner)
