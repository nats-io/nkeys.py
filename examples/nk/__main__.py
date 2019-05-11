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
import argparse, sys
import asyncio
import os
import signal
import nkeys
import base64

def show_usage():
    usage = """usage: nk [-h] [--inkey INKEY] [--sign SIGN] [--sigfile SIGFILE]
          [--verify VERIFY]

Example:

# Signining

nk --inkey user.nkey --sign nonce.data

# Verifying

nk --inkey user.nkey --verify nonce.data --sigfile nonce.sig
Verified OK

"""
    print(usage, file=sys.stderr)

def show_usage_and_die():
    show_usage()
    sys.exit(1)

def run():
    parser = argparse.ArgumentParser()
    parser.add_argument('--inkey', default='')
    parser.add_argument('--sign', default='')
    parser.add_argument('--sigfile', default='')
    parser.add_argument('--verify', default='')
    args = parser.parse_args()
    if len(args.inkey) <= 0:
        show_usage_and_die()

    # Create keypair from seed.
    seed = None
    with open(args.inkey, 'rb', buffering=0) as f:
        seed = bytearray(os.fstat(f.fileno()).st_size)
        f.readinto(seed)

    if len(args.sign) > 0:
        data = ''
        with open(args.sign, 'rb', buffering=0) as f:
            data = f.read()
        user = nkeys.from_seed(seed)
        signed = user.sign(data)
        result = base64.b64encode(signed)
        print(result.decode())
        sys.exit(0)

    if len(args.verify) > 0:
        data = ''
        with open(args.verify, 'rb', buffering=0) as f:
            data = f.read()

        signed_data = ''
        with open(args.sigfile, 'rb', buffering=0) as f:
            encoded_data = f.read()
            signed_data = base64.b64decode(encoded_data)

        user = nkeys.from_seed(seed)
        if user.verify(data, signed_data):
            print("Verified OK")
            sys.exit(0)

if __name__ == '__main__':
    run()
