#! /usr/bin/env python3
import binascii
import hashlib

import ecdsa

# demo public key
pubkey_base64 = "9vxNdELoMlz7BnbYQMW5P5pLIFwt/90lyCxXDYYMZArcSdxdTNnJZA+D3ZsCfeWOKfKYF1UAsntHpciGJHw5wA=="

# message to verify
message_hex = "9623c4100512254113214020922500000b5cef07c4409ddb45e494aaa4b6d0bb4154b8904daec942bef0fdfc37f110ad5cd062c679e7f24fc559df983426ccf9a4175c794f09cc86acb95356d2eff4f602759e7e533700c4205493ed9492117c40565084a88ad1ecc8f5159ae10a1ce47ab74da70f230bf161c440314691c79a3364c367ee5343a8918da70c27b6b6176fffe8b0c580d99734fb04734d4bdd6a2a93703d84df5891ddd7eca7ee4de2d6f257802a4e765cb17e304b"

pubkey_bytes = binascii.a2b_base64(pubkey_base64)
vk = ecdsa.VerifyingKey.from_string(pubkey_bytes, curve=ecdsa.NIST256p, hashfunc=hashlib.sha256)

message_bytes = binascii.unhexlify(message_hex)

try:
    vk.verify(message_bytes[-64:], message_bytes[:-66])
    print("Signature successfully verified")
except Exception as e:
    print(e)
