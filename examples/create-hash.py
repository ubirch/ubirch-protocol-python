import base64
import hashlib
import json
import sys

if len(sys.argv) < 2:
    print("usage:")
    print(
        """python3 ./create-hash.py '{"id": "605b91b4-49be-4f17-93e7-f1b14384968f", "ts": 1585838578, "data": 1234567890}'""")
    sys.exit()

print("   input: " + sys.argv[1])
message = json.loads(str(sys.argv[1]))

# create a compact rendering of the message to ensure determinism when creating the hash
serialized = json.dumps(message, separators=(',', ':'), sort_keys=True).encode()
print("rendered: " + serialized.decode())

# calculate hash of message
message_hash = hashlib.sha256(serialized).digest()
print("    hash: " + base64.b64encode(message_hash).decode())
