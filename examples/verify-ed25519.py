import binascii
import hashlib

import ed25519

# public key
pubkey = "okA7krya3TZbPNEv8SDQIGR/hOppg/mLxMh+D0vozWY="

# message to verify
message = "9623c4109d3c78ff22f34441a5d185c636d486ffc4408033ca8417150ef3ec2bebd7a9b35c8d3d6093d7a37a3025a6d236a088d4760796041c6bf6be8e7a834cea76f071135fcdd9216557f959e8d24d20a114d2ad0a00b86a3351426a4839535256716e693536486745555661673d3dc4408087f6bd6a4b2e321f1d27514dcafe7843d8336fb312ffd3b7205986647fb567a96b09dcb423ddcfd80013e083f29de2ccc4fb68529984ac8873afecd1d7f700"

vk = ed25519.VerifyingKey(pubkey, encoding='base64')

message_bytes = binascii.a2b_hex(message)  # for hex encoded messages
# message_bytes = binascii.a2b_base64(message)  # for base64 encoded messages

try:
    vk.verify(message_bytes[-64:], hashlib.sha512(message_bytes[:-66]).digest())
    print("Signature successfully verified")
except Exception as e:
    print(e)
