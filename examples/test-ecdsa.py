#! /usr/bin/env python3
import hashlib

import ecdsa

TEST_PRIV = bytes.fromhex("8f827f925f83b9e676aeb87d14842109bee64b02f1398c6dcdd970d5d6880937")
TEST_PUBL = bytes.fromhex("55f0feac4f2bcf879330eff348422ab3abf5237a24acaf0aef3bb876045c4e532fbd6cd8e265f6cf28b46e7e4512cd06ba84bcd3300efdadf28750f43dafd771")

sk = ecdsa.SigningKey.from_string(TEST_PRIV, curve=ecdsa.NIST256p, hashfunc=hashlib.sha256)
vk = ecdsa.VerifyingKey.from_string(TEST_PUBL, curve=ecdsa.NIST256p, hashfunc=hashlib.sha256)

CHAINED_MESSAGES = [
    bytearray(bytes.fromhex(
        "9623c4106eac4d0b16e645088c4622e7451ea5a1c44000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ccee01c4401fdd132be93216aa844b1d1a0838f1664babfa1fedab7b25ce48d0c9e124480b6c76e1780e877bda664c6d5795b2f0fe6660f78a27afb1228d84f37e92839b94")),
    bytearray(bytes.fromhex(
        "9623c4106eac4d0b16e645088c4622e7451ea5a1c4401fdd132be93216aa844b1d1a0838f1664babfa1fedab7b25ce48d0c9e124480b6c76e1780e877bda664c6d5795b2f0fe6660f78a27afb1228d84f37e92839b94ccee02c440ecd0676ac764a3b939f34422dc2cf56ebc7bbe2bcb3c7febc606e5832c38f60392c43371be134df6cf99301108bc5f09f1d04763427e79379d25a6923c2fcfcc")),
    bytearray(bytes.fromhex(
        "9623c4106eac4d0b16e645088c4622e7451ea5a1c440ecd0676ac764a3b939f34422dc2cf56ebc7bbe2bcb3c7febc606e5832c38f60392c43371be134df6cf99301108bc5f09f1d04763427e79379d25a6923c2fcfccccee03c440d3fcc18a4bec661a803af456873efaea3962afb2ec16955c0f7054ae6b0a169f00d2d86a74976f299a270a3450798b3cc43b2162c036ba76d8244279b044211e"))
]

for i, message in enumerate(CHAINED_MESSAGES):
    print("verifying message {}".format(i))
    vk.verify(message[-64:], hashlib.sha256(message[0:-66]).digest(), hashfunc=hashlib.sha256)