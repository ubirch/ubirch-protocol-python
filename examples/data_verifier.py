import binascii
import hashlib
import json

import requests

VERIFICATION_SERVICE = "https://verify.prod.ubirch.com/api/upp/verify/anchor"

with open("data_to_verify.json") as f:
    message = json.load(f)

# create a compact rendering of the message to ensure determinism when creating the hash
serialized = json.dumps(message, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode()
print("rendered data:\n\t{}\n".format(serialized.decode()))

# calculate hash of message
data_hash = hashlib.sha256(serialized).digest()
print("hash [base64]:\n\t{}\n".format(binascii.b2a_base64(data_hash, newline=False).decode()))

# verify existence of the hash in the UBIRCH backend
r = requests.post(
    url=VERIFICATION_SERVICE,
    headers={'Accept': 'application/json', 'Content-Type': 'text/plain'},
    data=binascii.b2a_base64(data_hash, newline=False)
)

if 200 <= r.status_code < 300:
    print("verification successful:\n\t{}\n".format(r.content.decode()))
else:
    print("verification FAIL: ({})\n\tdata hash could not be verified\n".format(r.status_code))
