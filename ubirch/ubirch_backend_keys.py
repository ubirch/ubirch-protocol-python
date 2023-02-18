
##
# @file ubirch_backend_keys.py
# ubirch backend keys getter functions
#
# @author Waldemar Gruenwald
#
# @copyright Copyright (c) 2023 ubirch GmbH.
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

import hashlib, binascii, ecdsa, ed25519
from uuid import UUID

ECDSA_TYPE = "ecdsa"
EDDSA_TYPE = "ed25519"

KEYS = {
    "dev":{
        "uuid":"9d3c78ff-22f3-4441-a5d1-85c636d486ff",
        "vk":{
            "ed25519":"39ff77632b034d0eba6d219c2ff192e9f24916c9a02672acb49fd05118aad251",
            "ecdsa":"2e753c064bc671940fcb98165542fe3c70340cff5d53ad47f0304ef2166f4f223b9572251b5fe8aee54c4fb812da79590caf501beba0911b7fcd3add2eb0180c"    
        }
    },
    "demo":{
        "uuid":"07104235-1892-4020-9042-00003c94b60b",
        "vk":{
            "ed25519":"a2403b92bc9add365b3cd12ff120d020647f84ea6983f98bc4c87e0f4be8cd66",
            "ecdsa":"c66fa222898146347741dbcb26b184d4e06cddb01ff04238f457e006b891937ea7e115185fed2c9ab60af2d66497a2e1aedf65ce38941ab5c68a3468544f948c"    
        }
    },
    "prod":{
        "uuid":"10b2e1a4-56b3-4fff-9ada-cc8c20f93016",
        "vk":{
            "ed25519":"ef8048ad06c0285af0177009381830c46cec025d01d86085e75a4f0041c2e690",
            "ecdsa":"a49758a0937437741314c0558d955089ed61860ba64154f2da45fd23b9178d2ca8225e3410e6bd317db848100004157bc55d88162d4a58c9c2d5a2ce22f3908d"    
        }
    }
}

def get_backend_environments() -> list:
    """!
    Getter to list the available backend environments.
    @return available Environments
    """
    return list(KEYS.keys())

def get_backend_uuid(env: str = "demo") -> UUID:
    """!
    Getter function for environment (`env`) specific backend UUID
    @param env Environment of the backend, can be `"dev"`, `"demo"`, or `"prod"`. Default is `"demo"`
    @return the UUID of the backend
    """
    return UUID(hex=KEYS[env]["uuid"])

def get_backend_verifying_key(env: str = "demo", key_type: str = EDDSA_TYPE) -> ed25519.VerifyingKey or ecdsa.VerifyingKey:
    """!
    Getter function for environment (`env`) specific backend verification key
    @param env Environment of the backend, can be `"dev"`, `"demo"`, or `"prod"`. Default is `"demo"`
    @param key_type is the cryptographic algorithm for the requested key, can be `"ed25519"` of `"ecdsa"`
    @return the key_type/algorithm specific public key
    """
    if key_type == EDDSA_TYPE:
        return ed25519.VerifyingKey(KEYS[env]["vk"][EDDSA_TYPE], encoding="hex")
    elif key_type == ECDSA_TYPE:
        return ecdsa.VerifyingKey.from_string(binascii.unhexlify(KEYS[env]["vk"][ECDSA_TYPE]), curve=ecdsa.NIST256p, hashfunc=hashlib.sha256)
