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

import pytest
import nkeys
import base64
import os


def test_from_seed_keypair():
    seed = "SUAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU"
    kp = nkeys.from_seed(bytearray(seed.encode()))
    assert type(kp) is nkeys.KeyPair


def test_keypair_sign_nonce():
    seed = "SUAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU"
    kp = nkeys.from_seed(bytearray(seed.encode()))
    raw = kp.sign(b"PXoWU7zWAMt75FY")
    sig = base64.b64encode(raw)
    assert sig == b'ZaAiVDgB5CeYoXoQ7cBCmq+ZllzUnGUoDVb8C7PilWvCs8XKfUchAUhz2P4BYAF++Dg3w05CqyQFRDiGL6LrDw=='


def test_from_seed_keypair_bad_padding():
    with pytest.raises(nkeys.ErrInvalidSeed):
        seed = "UAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU"
        nkeys.from_seed(bytearray(seed.encode()))


def test_from_seed_keypair_invalid_seed():
    with pytest.raises(nkeys.ErrInvalidSeed):
        seed = "AUAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU"
        nkeys.from_seed(bytearray(seed.encode()))

    with pytest.raises(nkeys.ErrInvalidSeed):
        seed = ""
        nkeys.from_seed(bytearray(seed.encode()))


def test_from_seed_keypair_valid_prefix_byte():
    seeds = [
        "SNAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU",
        "SCAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU",
        "SOAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU",
        "SUAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU"
    ]
    for seed in seeds:
        nkeys.from_seed(bytearray(seed.encode()))


def test_from_seed_keypair_invalid_public_prefix_byte():
    seeds = [
        b'SBAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU',
        b'SDAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU',
        b'PWAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU',
        b'PMAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU'
    ]
    with pytest.raises(nkeys.ErrInvalidPrefixByte):
        for seed in seeds:
            nkeys.from_seed(bytearray(seed))


def test_keypair_wipe():
    seed = "SUAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU"
    kp = nkeys.from_seed(bytearray(seed.encode()))
    assert kp._keys is not None

    kp.wipe()
    with pytest.raises(AttributeError):
        kp._keys
    with pytest.raises(AttributeError):
        kp._seed


def test_keypair_public_key():
    seed = "SUAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU"
    encoded_seed = bytearray(seed.encode())
    kp = nkeys.from_seed(encoded_seed)

    assert kp._public_key is None
    assert kp.public_key == "UCK5N7N66OBOINFXAYC2ACJQYFSOD4VYNU6APEJTAVFZB2SVHLKGEW7L"

    # Confirm that the public key is wiped as well.
    kp.wipe()
    with pytest.raises(AttributeError):
        kp._public_key


def test_keypair_use_seed_to_verify_signature():
    seed = "SUAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU"
    encoded_seed = bytearray(seed.encode())
    kp = nkeys.from_seed(encoded_seed)
    nonce = b'NcMQZSlX2lZ3Y4w'
    sig = kp.sign(nonce)
    assert kp.verify(nonce, sig)
    with pytest.raises(nkeys.ErrInvalidSignature):
        kp.verify(nonce + b'asdf', sig)


def test_keypair_seed_property():
    seed = bytearray(
        b"SUAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU"
    )
    kp = nkeys.from_seed(seed)
    assert kp.seed == bytearray(
        b"SUAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU"
    )

    # Throw away the seed.
    kp.wipe()

    with pytest.raises(nkeys.ErrInvalidSeed):
        kp.seed


def test_keypair_public_key_bytes():
    seed = "SUAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU"
    encoded_seed = bytearray(seed.encode())
    kp = nkeys.from_seed(encoded_seed)

    assert kp._public_key is None
    assert kp.public_key == b"UCK5N7N66OBOINFXAYC2ACJQYFSOD4VYNU6APEJTAVFZB2SVHLKGEW7L"

    # Confirm that the public key is wiped as well.
    kp.wipe()
    with pytest.raises(AttributeError):
        kp._public_key


def test_keypair_private_key():
    seed = "SUAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU"
    encoded_seed = bytearray(seed.encode())
    kp = nkeys.from_seed(encoded_seed)
    assert kp._public_key is None

    priv = kp.private_key
    assert priv == b"PDC2WWLK67NUTFW7ZH5A7FOPZC32VXYZYWYNQMQ6RQWP2FEEF6KDVFOW7W7PHAXEGS3QMBNABEYMCZHB6K4G2PAHSEZQKS4Q5JKTVVDCJORA"

    # Confirm that the private_key is wiped as well.
    kp.wipe()
    with pytest.raises(AttributeError):
        kp._keys
    with pytest.raises(AttributeError):
        kp._private_key


def test_roundtrip_seed_encoding(prefix):
    # This test is a low-tech property test in disguise,
    # testing the property:
    #   decode . encode == identity
    # Using a proper framework like hypothesis might be preferable.
    num_trials = 100
    raw_seeds = [os.urandom(32) for _ in range(num_trials)]
    for raw_seed in raw_seeds:
        encoded_seed = nkeys.encode_seed(raw_seed, prefix)
        decoded_prefix, decoded_seed = nkeys.decode_seed(encoded_seed)
        assert prefix == decoded_prefix
        assert raw_seed == decoded_seed
