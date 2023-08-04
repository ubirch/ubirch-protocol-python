import binascii
import hashlib
import json
import sys

usage_msg = """\n usage:
        python3 calculate-hash.py '{"id": "605b91b4-49be-4f17-93e7-f1b14384968f", "ts": 1585838578, "data": 1234}'
 or
        python3 calculate-hash.py <filename>.json """

if len(sys.argv) < 2:
    print(usage_msg)
    sys.exit()

if sys.argv[1].startswith('{') and sys.argv[1].endswith('}'):
    message = json.loads(sys.argv[1])
elif sys.argv[1].endswith('.json'):
    with open(sys.argv[1]) as f:
        message = json.load(f)
else:
    print(" invalid input: " + sys.argv[1] + usage_msg)
    sys.exit()

print(" input: " + str(message))

# create a compact rendering of the message to ensure determinism when creating the hash
serialized = json.dumps(message, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode()
print(" rendered: " + serialized.decode())

# calculate SHA256 hash of message
message_hash = hashlib.sha256(serialized).digest()
print(" SHA256 hash: " + binascii.b2a_base64(message_hash).decode().rstrip('\n'))

# calculate SHA512 hash of message
message_hash = hashlib.sha512(serialized).digest()
print(" SHA512 hash: " + binascii.b2a_base64(message_hash).decode())
