import hashlib, binascii, ecdsa, ed25519
from uuid import UUID


UBIRCH_UUIDS = {
    "dev": UUID(hex="9d3c78ff-22f3-4441-a5d1-85c636d486ff"),  # NOTE: dev environment is not reliable
    "demo": UUID(hex="07104235-1892-4020-9042-00003c94b60b"),
    "prod": UUID(hex="10b2e1a4-56b3-4fff-9ada-cc8c20f93016")
}

UBIRCH_PUBKEYS_ED = {
    "dev": ed25519.VerifyingKey("39ff77632b034d0eba6d219c2ff192e9f24916c9a02672acb49fd05118aad251", encoding="hex"),
    "demo": ed25519.VerifyingKey("a2403b92bc9add365b3cd12ff120d020647f84ea6983f98bc4c87e0f4be8cd66", encoding="hex"),
    "prod": ed25519.VerifyingKey("ef8048ad06c0285af0177009381830c46cec025d01d86085e75a4f0041c2e690", encoding="hex")
}

UBIRCH_PUBKEYS_EC = {
    "dev": ecdsa.VerifyingKey.from_string(binascii.unhexlify(
        "2e753c064bc671940fcb98165542fe3c70340cff5d53ad47f0304ef2166f4f223b9572251b5fe8aee54c4fb812da79590caf501beba0911b7fcd3add2eb0180c"
    ), curve=ecdsa.NIST256p, hashfunc=hashlib.sha256),
    "demo": ecdsa.VerifyingKey.from_string(binascii.unhexlify(
        "c66fa222898146347741dbcb26b184d4e06cddb01ff04238f457e006b891937ea7e115185fed2c9ab60af2d66497a2e1aedf65ce38941ab5c68a3468544f948c"
    ), curve=ecdsa.NIST256p, hashfunc=hashlib.sha256),
    "prod": ecdsa.VerifyingKey.from_string(binascii.unhexlify(
        "a49758a0937437741314c0558d955089ed61860ba64154f2da45fd23b9178d2ca8225e3410e6bd317db848100004157bc55d88162d4a58c9c2d5a2ce22f3908d"
    ), curve=ecdsa.NIST256p, hashfunc=hashlib.sha256),
}