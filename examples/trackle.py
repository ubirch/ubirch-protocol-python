import sys

import msgpack
import binascii

line = open(sys.argv[1]).read().rstrip()
print(repr(line))
msg = binascii.unhexlify(line)
print(repr(msgpack.unpackb(msg, raw=True)))