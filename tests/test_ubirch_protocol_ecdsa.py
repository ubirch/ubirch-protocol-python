# ubirch protocol tests
#
# @author Matthias L. Jugel
#
# Copyright (c) 2018 ubirch GmbH.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import binascii
import hashlib
import logging
import os
import unittest
from uuid import UUID

import ecdsa
import ed25519

import ubirch
from ubirch.ubirch_protocol import SIGNED, CHAINED

logger = logging.getLogger(__name__)
logging.basicConfig(format='%(asctime)s %(name)20.20s %(levelname)-8.8s %(message)s',
                    level=logging.DEBUG)

# helper for keyloading
def _vk_bytes_to_vk(vk_bytes : bytes) -> ecdsa.VerifyingKey:
    return ecdsa.VerifyingKey.from_string(binascii.unhexlify(vk_bytes), curve=ecdsa.NIST256p, hashfunc=hashlib.sha256)

def _sk_bytes_to_sk(sk_bytes : bytes) -> ecdsa.SigningKey:
    return ecdsa.SigningKey.from_string(binascii.unhexlify(sk_bytes), curve=ecdsa.NIST256p, hashfunc=hashlib.sha256)

##################################################################################
#                             Data for Normal testing                            #
##################################################################################
# keys defined multiple times in case tests should be modified at some point

# normal signed upps
NRM_SIGNED_UPPS_UUID = UUID(hex="6eac4d0b-16e6-4508-8c46-22e7451ea5a1")
NRM_SIGNED_UPPS_PRIV = "8f827f925f83b9e676aeb87d14842109bee64b02f1398c6dcdd970d5d6880937"
NRM_SIGNED_UPPS_PUB = "55f0feac4f2bcf879330eff348422ab3abf5237a24acaf0aef3bb876045c4e532fbd6cd8e265f6cf28b46e7e4512cd06ba84bcd3300efdadf28750f43dafd771"
NRM_SIGNED_UPP = ( # tuple of upp/payload
    bytes.fromhex(
        "9522c4106eac4d0b16e645088c4622e7451ea5a100c4207bc6b089b5c33f1e0d319795851c257f11cdb7ea33052acd17f0ae2c1bdf8814c44075e08e6390e4160cd9703a322f6bd697d2aa1917b3032c039ae15ce03f1fb9f2510d130196514c661934cd63ef55a34e1d6e8f8c6f50f25479032c6ac397af3e" # upp
    ),
    bytes.fromhex("7bc6b089b5c33f1e0d319795851c257f11cdb7ea33052acd17f0ae2c1bdf8814") # payload
)

# normal chained upps
NRM_CHAINED_UPPS_UUID = UUID(hex="6eac4d0b-16e6-4508-8c46-22e7451ea5a1")
NRM_CHAINED_UPPS_PRIV = "8f827f925f83b9e676aeb87d14842109bee64b02f1398c6dcdd970d5d6880937"
NRM_CHAINED_UPPS_PUB = "55f0feac4f2bcf879330eff348422ab3abf5237a24acaf0aef3bb876045c4e532fbd6cd8e265f6cf28b46e7e4512cd06ba84bcd3300efdadf28750f43dafd771"
NRM_CHAINED_UPPS = [
    # tuple of upp/payload
    ( 
        bytes.fromhex(
            "9623c4106eac4d0b16e645088c4622e7451ea5a1c440cfeb43c9268f4b3f325e8f13c7a66b2308d21bfa7fba8d5f21203f6692f723e7e8d753ceffcb09891513137a69f44c9dbfb1c87f47a41372b8b9a0a31497ed5d00c420cb617098b5cc7b077b322a39b3f380f9ef37c9d6c208d1ed63fbe906666bf1eec440af033a25ee94cbec8ab614f85b0f7724212ae9e9851fdc4455f007ff2f753b59abc783fdc2771e1a68067a78d1d912b1212f39de98c2e8b20ffe1161a17950a6" # upp
        ),
        bytes.fromhex("cb617098b5cc7b077b322a39b3f380f9ef37c9d6c208d1ed63fbe906666bf1ee") # payload
    ),
    ( 
        bytes.fromhex(
            "9623c4106eac4d0b16e645088c4622e7451ea5a1c440af033a25ee94cbec8ab614f85b0f7724212ae9e9851fdc4455f007ff2f753b59abc783fdc2771e1a68067a78d1d912b1212f39de98c2e8b20ffe1161a17950a600c420733cf7055c16679ab99090a433434b98051d2fb75ade78b06bd6db1cb8a799f2c4409d3cc5bcd2d0c12605b82f7b3bc1de5d602314a84deab555180e8550ba8e34530b8a4037287007a4c091fe8701913c980cf8ae017f087c3709c2b45aa6c97bf6" # upp
        ),
        bytes.fromhex("733cf7055c16679ab99090a433434b98051d2fb75ade78b06bd6db1cb8a799f2") # payload
    ),
    ( 
        bytes.fromhex(
            "9623c4106eac4d0b16e645088c4622e7451ea5a1c4409d3cc5bcd2d0c12605b82f7b3bc1de5d602314a84deab555180e8550ba8e34530b8a4037287007a4c091fe8701913c980cf8ae017f087c3709c2b45aa6c97bf600c4200b06bcb61ebdae4dfb009fa606edb4d8914ecd9d01a505882f30f5faf403ec85c440ec9932d6a2b0f3b1edd4a1bd4e69f69754361a3a0b4c1bd8632fb18c041b37c9a9d03e47a627a03a6a8bdaff475dda7e9fbe5ae8088dd213325a8afc5cceaf10" # upp
        ),
        bytes.fromhex("0b06bcb61ebdae4dfb009fa606edb4d8914ecd9d01a505882f30f5faf403ec85") # payload
    ),
]

##################################################################################
#                              Data for SIM testing                              #
##################################################################################
# keys defined multiple times in case tests should be modified at some point

# sim signed UPPs
SIM_SIGNED_UPPS_UUID = UUID(hex="07104233-1892-4020-9042-00002f6d169d")
SIM_SIGNED_UPPS_PUB = "3f7f2091c1486ce821f9c61d45bfc76b7b629241ca2e920730043307bc1e7be977ffd3346badbc66002a497416bd5cb9132002649259604b2dd6cd7188f423f3"
SIM_SIGNED_UPPS = [
    # tuples of upp/payload
    (
        bytes.fromhex(
            "9522c4100710423318924020904200002f6d169d00c420c86b9e8dc30aba9ae823b9735eeac26a9f8139f7528ea9599c89c5d8be52a093c44039865534ed13ed4152b99d5387f9b6b2faba800f811db73066eab48989fcc1c7a0df8dec55d5599f858dd78f9e77baf4dbc696663417e08316f2d9f660004dbe" # upp
        ), 
        bytes.fromhex("c86b9e8dc30aba9ae823b9735eeac26a9f8139f7528ea9599c89c5d8be52a093") # payload
    ),
    (
        bytes.fromhex(
            "9522c4100710423318924020904200002f6d169d00c42020977c685c1d230b0e58b08846434924ad345694afbe2b3bac8fd3885ccc3a51c440c5baf5853da4b15b6c861bd04c6cb721e3b62ce37e17fbcb04e92ed483fee083bd68d9e99fec16cf332264d20c01be86f1aba9a20ecea10d7afd1992b0633bf2" # upp
        ),
        bytes.fromhex("20977c685c1d230b0e58b08846434924ad345694afbe2b3bac8fd3885ccc3a51") # payload
    ),
    (
        bytes.fromhex(
            "9522c4100710423318924020904200002f6d169d00c42057b61a0b0d73ec7be87711f5d46273521e03197b6ce1e5dea45c7865b25456d7c440b1217b28b38494d037af9c51e59c363bb134e131690325a3a58fdc4cf32e5f7517fd63fe7e06ab8ed8207ce178ae70fc8dec5c1647baa29bf21230309e01ec41", # upp
        ),
        bytes.fromhex("57b61a0b0d73ec7be87711f5d46273521e03197b6ce1e5dea45c7865b25456d7") # payload
    ),
    (
        bytes.fromhex(
            "9522c4100710423318924020904200002f6d169d00c4205bb3fbd13b9e2d4c5e7499c02320e8db74edec1fd66cb1dd06ab3e3b72bccdaac4406601058cb6dc81254fdc65363c89de673220be111a3c015e0f539a4d0500ce0a5ce7f67c1b7182930f8fbed37614d25be004a5a4885f5e75435f88ea51de237f" # upp
        ),
        bytes.fromhex("5bb3fbd13b9e2d4c5e7499c02320e8db74edec1fd66cb1dd06ab3e3b72bccdaa") # payload
    )
]
# sim chained upps
SIM_CHAINED_UPPS_UUID = UUID(hex="07104233-1892-4020-9042-00002f6d169d")
SIM_CHAINED_UPPS_PUB = "3f7f2091c1486ce821f9c61d45bfc76b7b629241ca2e920730043307bc1e7be977ffd3346badbc66002a497416bd5cb9132002649259604b2dd6cd7188f423f3"
SIM_CHAINED_UPPS = [
    # tuples of upp/payload
    (
        bytes.fromhex(
            "9623c4100710423318924020904200002f6d169dc4406601058cb6dc81254fdc65363c89de673220be111a3c015e0f539a4d0500ce0a5ce7f67c1b7182930f8fbed37614d25be004a5a4885f5e75435f88ea51de237f00c420d2233cd27a9ad0493433e144344add27c524b09793a8b65dea4d4e72e9335ddec4403aa098e5f65bf8047ba8a2ffcca17b22977bd29a772124f33fc128e6ec88a7245557c432c0ac9af22d157de03240ffc43e125fa345082fd344ecade6c470f846"
        ),
        bytes.fromhex(
            "d2233cd27a9ad0493433e144344add27c524b09793a8b65dea4d4e72e9335dde"
        )
    ),
    (
        bytes.fromhex(
            "9623c4100710423318924020904200002f6d169dc4403aa098e5f65bf8047ba8a2ffcca17b22977bd29a772124f33fc128e6ec88a7245557c432c0ac9af22d157de03240ffc43e125fa345082fd344ecade6c470f84600c4200d5be1990e1d880acc08c4e88b5324947cdb5c3edf1a5470adbd217b69498966c44082ba95220d76f93461d7af6a5f7f45c8490ebdcfcf1c0428762b4da9c53ee3d2c70ec35f1ed61f82cd716f6394734fd6aafdb528846c259a9c94569f71e9dc96"
        ),
        bytes.fromhex(
            "0d5be1990e1d880acc08c4e88b5324947cdb5c3edf1a5470adbd217b69498966"
        )
    ),
    (
        bytes.fromhex(
            "9623c4100710423318924020904200002f6d169dc44082ba95220d76f93461d7af6a5f7f45c8490ebdcfcf1c0428762b4da9c53ee3d2c70ec35f1ed61f82cd716f6394734fd6aafdb528846c259a9c94569f71e9dc9600c42050d8537ff48d337d4cddce62cad2e436071616571100ee41ece80d1b7af50045c440a97bc28c55e785b9b070e3c48146dcf08de893754ffe9f111785996f664df47528222060ebf309b201b56db02f8610ff458298824aa4f194df5023211f3a5d51"
        ),
        bytes.fromhex(
            "50d8537ff48d337d4cddce62cad2e436071616571100ee41ece80d1b7af50045"
        )
    ),
    (
        bytes.fromhex(
            "9623c4100710423318924020904200002f6d169dc440a97bc28c55e785b9b070e3c48146dcf08de893754ffe9f111785996f664df47528222060ebf309b201b56db02f8610ff458298824aa4f194df5023211f3a5d5100c4205e5e21637343130643d1971cefd801bfee7688bbab221ae9e444393fc5d5c870c4402d6df84f9a007f9a84efe4a33ff5decc68b70d01daf95fb4459f23cd35ff3c3d3911e293a3a904f7a21d31fee317ec76c5c69e0dafd5f9dde224dfd0d1bb12e5"
        ),
        bytes.fromhex(
            "5e5e21637343130643d1971cefd801bfee7688bbab221ae9e444393fc5d5c870"
        )
    )
]


# a simple implementation of the ubirch protocol, having a fixed single key (from fixtures)
class Protocol(ubirch.Protocol):
    sk = None
    vk = None

    def _sign(self, uuid: UUID, message: bytes) -> bytes:
        if isinstance(self.sk, ecdsa.SigningKey):
            # no hashing required here
            final_message = message
        elif isinstance(self.sk, ed25519.SigningKey):
            final_message = hashlib.sha512(message).digest() 
        else: 
            raise(ValueError("Signing Key is neither ed25519, nor ecdsa!"))    
        
        return self.sk.sign(final_message)

    def _verify(self, uuid: UUID, message: bytes, signature: bytes):
        if isinstance(self.vk, ecdsa.VerifyingKey):
            # no hashing required here
            final_message = message
        elif isinstance(self.vk, ed25519.VerifyingKey):
            final_message = hashlib.sha512(message).digest() 
        else: 
            raise(ValueError("Verifying Key is neither ed25519, nor ecdsa!"))    
         
        return self.vk.verify(signature, final_message)


class TestUbirchProtocolECDSA(unittest.TestCase):
    def test_sign_not_implemented(self):
        p = ubirch.Protocol()
        try:
            p.message_signed(NRM_SIGNED_UPPS_UUID, 0xEF, 1)
        except NotImplementedError as e:
            self.assertEqual(e.args[0], 'signing not implemented')

    def test_verify_not_implemented(self):
        p = ubirch.Protocol()
        try:
            p.verify_signature(NRM_SIGNED_UPPS_UUID, NRM_SIGNED_UPP[0])
        except NotImplementedError as e:
            self.assertEqual(e.args[0], 'verification not implemented')

    def test_create_signed_message(self):
        p = Protocol()
        p.sk = _sk_bytes_to_sk(NRM_SIGNED_UPPS_PRIV)
        p.vk = _vk_bytes_to_vk(NRM_SIGNED_UPPS_PUB)

        PAYLOAD_TYPE = 0xEE
        PAYLOAD = 7109

        # create chained upp
        message = p.message_signed(NRM_SIGNED_UPPS_UUID, PAYLOAD_TYPE, PAYLOAD)

        # check whether verifying it works
        self.assertEqual(p.verify_signature(NRM_SIGNED_UPPS_UUID, message), True)

        # unpack the UPP to check components
        unpacked = p.unpack_upp(message)

        # compare the payload type and payload
        self.assertEqual(unpacked[2], PAYLOAD_TYPE)
        self.assertEqual(unpacked[3], PAYLOAD)
        
    def test_create_chained_messages(self):
        p = Protocol()
        p.sk = _sk_bytes_to_sk(NRM_CHAINED_UPPS_PRIV)
        p.vk = _vk_bytes_to_vk(NRM_CHAINED_UPPS_PUB)

        last_signature = bytearray(b'\0'*64)
        PAYLOAD_TYPE = 0xEE

        # create three messages
        for i in range(0, 3):
            # create chained upp
            message = p.message_chained(NRM_CHAINED_UPPS_UUID, PAYLOAD_TYPE, i + 1)

            # check whether verifying it works
            self.assertEqual(p.verify_signature(NRM_CHAINED_UPPS_UUID, message), True)

            # unpack the UPP to check components
            unpacked = p.unpack_upp(message)

            # compare the prevsig
            self.assertEqual(unpacked[2], last_signature)

            # set the prevsig to the current sig
            last_signature = unpacked[5]

            # compare the payload type and payload
            self.assertEqual(unpacked[3], PAYLOAD_TYPE)
            self.assertEqual(unpacked[4], i + 1)

    def test_verify_signed_message(self):
        p = Protocol()
        p.sk = _sk_bytes_to_sk(NRM_SIGNED_UPPS_PRIV)
        p.vk = _vk_bytes_to_vk(NRM_SIGNED_UPPS_PUB)

        # verify the upp
        self.assertEqual(p.verify_signature(NRM_SIGNED_UPPS_UUID, NRM_SIGNED_UPP[0]), True)

        # unpack the upp
        unpacked = p.unpack_upp(NRM_SIGNED_UPP[0])

        # check if the type is right
        self.assertEqual(SIGNED, unpacked[0])

        # check the uuid
        self.assertEqual(NRM_SIGNED_UPPS_UUID.bytes, unpacked[1])

        # check the payload
        self.assertEqual(NRM_SIGNED_UPP[1], unpacked[3])

    def test_verify_chained_messages(self):
        p = Protocol()
        p.sk = _sk_bytes_to_sk(NRM_CHAINED_UPPS_PRIV)
        p.vk = _vk_bytes_to_vk(NRM_CHAINED_UPPS_PUB)

        prev = None

        # first element of upp is the actual upp, second one is the payload
        for upp in NRM_CHAINED_UPPS:
            # verify the upp
            self.assertEqual(p.verify_signature(NRM_CHAINED_UPPS_UUID, upp[0]), True)

            # unpack the upp
            unpacked = p.unpack_upp(upp[0])

            # check the uuid
            self.assertEqual(NRM_CHAINED_UPPS_UUID.bytes, unpacked[1])

            # check the payload
            self.assertEqual(upp[1], unpacked[4])

            # check the prevsig
            if prev != None:
                self.assertEqual(unpacked[2], prev)
            
            # set the prevsig
            prev = unpacked[-1]


class TestUbirchProtocolSIM(unittest.TestCase):
    @unittest.expectedFailure
    def test_verify_registration_message_sim_v1(self):
        loc = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))
        with open(os.path.join(loc, "v1.0-ecdsa-register.mpack"), "rb") as f:
            message = f.read()

        vk = "06784eaaf180c1091a135bfe4804306f696fc56a4a75d12e269bfcafb67498d5a963fb72aaaca9fa3209bdf9b34d249c493bd5cd0a4d3763e425c8f461af50a5"
        p = Protocol()
        p.vk = ecdsa.VerifyingKey.from_string(binascii.unhexlify(vk), curve=ecdsa.NIST256p, hashfunc=hashlib.sha256)

        unpacked = p.unpack_upp(message)

        self.assertEqual(p.verify_signature(None, bytearray(message)), True)
        self.assertEqual(vk, binascii.hexlify(unpacked[3][b'pubKey']).decode())

    @unittest.expectedFailure
    def test_verify_signed_message_sim_v1(self):
        loc = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))
        with open(os.path.join(loc, "v1.0-ecdsa-message.mpack"), "rb") as f:
            message = f.read()

        vk = "06784eaaf180c1091a135bfe4804306f696fc56a4a75d12e269bfcafb67498d5a963fb72aaaca9fa3209bdf9b34d249c493bd5cd0a4d3763e425c8f461af50a5"
        p = Protocol()
        p.vk = ecdsa.VerifyingKey.from_string(binascii.unhexlify(vk), curve=ecdsa.NIST256p, hashfunc=hashlib.sha256)

        unpacked = p.unpack_upp(message)
        logger.debug(repr(unpacked))

        self.assertEqual(p.verify_signature(UUID(bytes=unpacked[1]), bytearray(message)), True)
        self.assertEqual(hashlib.sha256(b"UBIRCH").digest(), unpacked[3])

    @unittest.expectedFailure
    def test_verify_registration_message_sim_v2(self):
        p = Protocol()
        p.vk = ecdsa.VerifyingKey.from_string(binascii.unhexlify(self.vkhex), curve=ecdsa.NIST256p, hashfunc=hashlib.sha256)

        unpacked = p.unpack_upp(message)
        logger.debug(repr(unpacked))

        self.assertEqual(p.verify_signature(UUID(bytes=unpacked[1]), message), True)
        self.assertEqual(vk, binascii.hexlify(unpacked[3]['pubKey']).decode())

    def test_verify_signed_message_sim_v2(self):
        p = Protocol()
        p.vk = _vk_bytes_to_vk(SIM_SIGNED_UPPS_PUB)

        # first element of upp is the actual upp, second one is the payload
        for upp in SIM_SIGNED_UPPS:
            # verify the upp
            self.assertEqual(p.verify_signature(SIM_SIGNED_UPPS_UUID, upp[0]), True)

            # unpack the upp
            unpacked = p.unpack_upp(upp[0])

            # check the uuid
            self.assertEqual(SIM_SIGNED_UPPS_UUID.bytes, unpacked[1])

            # check the payload
            self.assertEqual(upp[1], unpacked[3])

    def test_verify_chained_message_sim_v2(self):
        p = Protocol()
        p.vk = _vk_bytes_to_vk(SIM_CHAINED_UPPS_PUB)
        prev = None

        # first element of upp is the actual upp, second one is the payload
        for upp in SIM_CHAINED_UPPS:
            # verify the upp
            self.assertEqual(p.verify_signature(SIM_CHAINED_UPPS_UUID, upp[0]), True)

            # unpack the upp
            unpacked = p.unpack_upp(upp[0])

            # check the uuid
            self.assertEqual(SIM_CHAINED_UPPS_UUID.bytes, unpacked[1])

            # check the payload
            self.assertEqual(upp[1], unpacked[4])

            # check the prevsig
            if prev != None:
                self.assertEqual(unpacked[2], prev)
            
            # set the prevsig
            prev = unpacked[-1]
