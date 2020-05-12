import binascii
import sys
from uuid import UUID

import msgpack

signed = 0x22
chained = 0x23

upp = binascii.unhexlify("")  # you can paste the hex string representation of the UPP here instead of passing a file

if not upp:
    upp = binascii.a2b_base64(
        "")  # you can paste the base64 string representation of the UPP here instead of passing a file

if not upp:
    if len(sys.argv) < 2:
        print("usage:")
        print("python3 ./unpack.py <binary-file-name>")
        sys.exit()

    with open(sys.argv[1], "rb") as f:
        upp = f.read()

try:
    unpacked = msgpack.unpackb(upp, raw=False)
except Exception:
    # try legacy version
    unpacked = msgpack.unpackb(upp, raw=True)

version = unpacked[0]
print("-  Version: 0x{:02x}".format(version))

uuid = UUID(binascii.hexlify(unpacked[1]).decode())
print("-     UUID: {}".format(str(uuid)))

if version == chained:
    prev_sign = unpacked[2]
    print("- prevSign: {}".format(binascii.hexlify(prev_sign).decode()))

type = unpacked[-3]
print("-     Type: 0x{:02x}".format(type))

payload = unpacked[-2]
print("-  Payload: {:s}".format(repr(payload)))

signature = unpacked[-1]
print("-     Sign: {:s}".format(binascii.hexlify(signature).decode()))
