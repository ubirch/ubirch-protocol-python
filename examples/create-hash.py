import base64
import hashlib
import json
import sys

if len(sys.argv) < 2:
    print("usage:")
    print(
        """  python3 ./create-hash.py '{"id":"7100c024-1e8e-4007-b25f-c056397e12b8","store":"ubirch","value":3000}' """)
    sys.exit(0)

print(sys.argv[1])
message = json.loads(str(sys.argv[1]))

# create a compact rendering of the message to ensure determinism when creating the hash
serialized = json.dumps(message, separators=(',', ':'), sort_keys=True).encode()

# calculate hash of message
message_hash = hashlib.sha256(serialized).digest()

# compare hash with expected value
print(base64.b64encode(message_hash).decode())
