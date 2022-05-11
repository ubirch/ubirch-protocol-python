import binascii
import sys
from uuid import UUID

import msgpack

signed = 0x22
chained = 0x23

usage = " usage:\n" \
        " python3 ./unpack.py [ <binary-file-name> | <UPP(hex)> | <UPP(base64)> ]"

if len(sys.argv) < 2:
    print(usage)
    sys.exit(1)

upp = b''
arg = sys.argv[1]

# try to get UPP from binary file
try:
    with open(arg, "rb") as f:
        upp = f.read()
except OSError:
    pass

if not upp:
    # try to parse argument as hex string representation of UPP
    try:
        upp = binascii.unhexlify(arg)
    except binascii.Error:
        pass

if not upp:
    # try to parse argument as base64 string representation of UPP
    try:
        upp = binascii.a2b_base64(arg)
    except Exception:
        print("unable to parse UPP from argument: \"{}\"".format(arg))
        print(usage)
        sys.exit(1)

if not (upp[0] == 0x95 or upp[0] == 0x96):
    print("invalid UPP")
    print(usage)
    sys.exit(1)

# unpack msgpack formatted UPP
if upp[1] >> 4 == 2:  # version 2
    unpacked = msgpack.unpackb(upp)
elif upp[1] >> 4 == 1:  # version 1 (legacy)
    unpacked = msgpack.unpackb(upp, raw=True)
else:
    print("invalid UPP version")
    print(usage)
    sys.exit(1)

version = unpacked[0]
print("-    Version: 0x{:02x}".format(version))

uuid = UUID(binascii.hexlify(unpacked[1]).decode())
print("-       UUID: {}".format(str(uuid)))

if version == chained:
    prev_sign = unpacked[2]
    print("- prev.Sign.: {}".format(binascii.b2a_base64(prev_sign).decode().rstrip("\n")))
    print("       [hex]: {:s} ({:d} bytes)".format(binascii.hexlify(prev_sign).decode(), len(prev_sign)))

payload_type = unpacked[-3]
print("-       Type: 0x{:02x}".format(payload_type))

payload = unpacked[-2]
if type(payload) is bytes:
    print("-    Payload: {:s}".format(binascii.b2a_base64(payload).decode().rstrip("\n")))
    print("       [hex]: {:s} ({:d} bytes)".format(binascii.hexlify(payload).decode(), len(payload)))
else:
    print("-    Payload: {:s}".format(repr(payload)))

signature = unpacked[-1]
print("-  Signature: {:s}".format(binascii.b2a_base64(signature).decode().rstrip("\n")))
print("       [hex]: {:s} ({:d} bytes)".format(binascii.hexlify(signature).decode(), len(signature)))
