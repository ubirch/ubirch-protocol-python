import time, json, pickle, hashlib, binascii, ecdsa, ed25519
from uuid import UUID
from requests import codes, Response

import ubirch
from ubirch.ubirch_protocol import UBIRCH_PROTOCOL_TYPE_REG, UBIRCH_PROTOCOL_TYPE_BIN, UNPACKED_UPP_FIELD_PREV_SIG

from ubirch_keys_and_uuids import UBIRCH_UUIDS, UBIRCH_PUBKEYS_EC, UBIRCH_PUBKEYS_ED

uuid = UUID(hex="e7c3738e-8796-4f9e-88ca-55926135542c")  # f5ded8a3-d462-41c4-a8dc-af3fd072a217
auth =          "c00e66b5-f345-4b33-97de-c223e58fcb11"   # xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

keystore_name = "devices.jks"
keystore_password = "keystore"  # 'XXXXXXXXXXX'

key_type = "ed25519"  # keytype can be 'ed25519' or 'ecdsa'
env = "demo"  # env can be 'prod', 'demo' or 'dev'

# Instead of using a pre-made wrapper around protocol, api and keystore we implement it ourself!
class Proto(ubirch.Protocol):
    def __init__(self, keystore: ubirch.KeyStore, key_type: str):
        super().__init__()
        self.__ks = keystore
        self.load_saved_signatures(uuid)

        if key_type == "ed25519":

            # check if the device already has keys or generate a new pair
            if not self.__ks.exists_signing_key(uuid):
                print("Generating new keypair with ed25519 algorithm")
                self.__ks.create_ed25519_keypair(uuid)

            if self.__ks._ks.entries.get(UBIRCH_UUIDS[env].hex + '_ecd', None) != None:
                # suffix-less pubkey found, delete it
                self.__ks._ks.entries.pop(UBIRCH_UUIDS[env].hex + '_ecd')

            self.__ks.insert_ed25519_verifying_key(UBIRCH_UUIDS[env], UBIRCH_PUBKEYS_ED[env])

        elif key_type == "ecdsa":

            # check if the device already has keys or generate a new pair
            if not self.__ks.exists_signing_key(uuid):
                print("Generating new keypair with ecdsa algorithm")
                self.__ks.create_ecdsa_keypair(uuid)

            if self.__ks._ks.entries.get(UBIRCH_UUIDS[env].hex, None) != None:
                # suffix-less pubkey found, delete it
                self.__ks._ks.entries.pop(UBIRCH_UUIDS[env].hex)

            self.__ks.insert_ecdsa_verifying_key(UBIRCH_UUIDS[env], UBIRCH_PUBKEYS_EC[env])

    def _sign(self, uuid: UUID, message: bytes):
        signing_key = self.__ks.find_signing_key(uuid)

        if isinstance(signing_key, ecdsa.SigningKey):
            # no hashing required here
            return signing_key.sign(message)

        elif isinstance(signing_key, ed25519.SigningKey):
            hashed_message = hashlib.sha512(message).digest()
            return signing_key.sign(hashed_message)

        else:
            raise (ValueError("Signing Key is neither ed25519, nor ecdsa! It's: " + str(type(signing_key))))

    def _verify(self, uuid: UUID, message: bytes, signature: bytes):
        verifying_key = self.__ks.find_verifying_key(uuid)

        if isinstance(verifying_key, ecdsa.VerifyingKey):
            # no hashing required here
            return verifying_key.verify(signature, message)

        elif isinstance(verifying_key, ed25519.VerifyingKey):
            hashed_message = hashlib.sha512(message).digest()
            return verifying_key.verify(signature, hashed_message)

        else:
            raise (ValueError("Verifying Key is neither ed25519, nor ecdsa! It's: " + str(type(verifying_key))))

        return verifying_key.verify(signature, final_message)

    def persist_signatures(self, uuid: UUID):
        signatures = self.get_saved_signatures()
        with open(uuid.hex + ".sig", "wb") as f:
            pickle.dump(signatures, f)

    def load_saved_signatures(self, uuid: UUID):
        try:
            with open(uuid.hex + ".sig", "rb") as f:
                signatures = pickle.load(f)
                print("loaded {} known signatures".format(len(signatures)))
                self.set_saved_signatures(signatures)
        except FileNotFoundError or EOFError:
            print("no existing saved signatures")
            pass

#======================== 'Receive' data ========================#
data = {
    "timestamp": time.time(),
    "temperature": 11.2,
    "humidity": 35.8,
    "status": "OK"
}

# ========== Setting up all parts of the Ubirch solution ==========#
keystore = ubirch.KeyStore(keystore_name, keystore_password)
# create a keystore for the device
# you could use your own key management tool instead

protocol = Proto(keystore, key_type)
# create an instance of the protocol with signature saving

api = ubirch.API(env=env)
api.set_authentication(uuid, auth)
# create an instance of the UBIRCH API and set the auth token

if not api.is_identity_registered(uuid):
    # check if the public key is registered at the ubirch key service and register it if necessary

    certificate = keystore.get_certificate(uuid)
    key_registration = protocol.message_signed(uuid, UBIRCH_PROTOCOL_TYPE_REG, certificate)
    # get the certificate and create the registration message

    response = api.register_identity(key_registration)
    # send the registration message and catch any errors that could have come up

    print("Registration response: ({}) {}".format(response.status_code, protocol.unpack_upp(response.content)))
    if response.status_code != codes.ok:
        raise Exception("Registration failed!")


#=========== Create and send a Ubirch protocol packet ==========#
# Hardcoded: For demonstration purpose only
hashed_data_hardcoded = hashlib.sha512(b'{"T": 11.2, "H": 35.8, "S": "OK", "ts":"1652452008"}"').digest()

serialized = json.dumps(data, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode()
# Create a compact rendering of the message to ensure determinism when creating the hash
# Serializes a JSON object to bytes like this '{"T": 11.2, "H": 35.8, "S": "OK", "ts":"1652452008"}'

hashed_data = hashlib.sha512(serialized).digest()
print("Message hash: {}".format(binascii.b2a_base64(hashed_data).decode().rstrip("\n")))
# Hash the message using SHA512

message_UPP = protocol.message_chained(uuid, ubirch.ubirch_protocol.UBIRCH_PROTOCOL_TYPE_BIN, hashed_data)
# Create a new chained protocol message with the message hash
# UBIRCH_PROTOCOL_TYPE_BIN is the type-code of a normal binary message: '0x00'

response = api.send(uuid, message_UPP)
# send the message to the Ubirch authentication service and catch any errors that could have come up

print("Response: ({})\n {}".format(response.status_code, protocol.unpack_upp(response.content)))
if response.status_code != codes.ok:
    raise Exception("Sending message failed!")

# ================== Response UPP verification ==================#
#= Verify that the response came from the backend =#
if protocol.verfiy_signature(UBIRCH_UUIDS[env], response.content) == True:
    print("Backend response signature successfully verified!")
else:
    raise Exception("Backend response signature verification FAILED!")

#= Verify that the UPP is correctly chained. =#
# The previous signature in the response UPP has to be the same as the sent UPPs Signature
_, signature_message_UPP = protocol.upp_msgpack_split_signature(message_UPP)
# _ is a throwaway variable for the rest of the UPP that is split

unpacked = protocol.unpack_upp(response.content)
signature_index = protocol.get_unpacked_index(unpacked[0], UNPACKED_UPP_FIELD_PREV_SIG)
# unpack the received upp to get its previous signature
previous_signature_in_UPP = unpacked[signature_index]

if signature_message_UPP == previous_signature_in_UPP:
    print("Sent UPP is correctly chained! The previous signature in the response UPP is the same as the sent UPPs signature")
else:
    raise Exception("The previous signature in the response UPP doesn't match the signature of our UPP!")

print("[✓] Successfully sent the UPP and verified the response!")
# the handle, verification and assert functions raise Errors on any kind of error - save to assume success

protocol.persist_signatures(uuid)
# save last signatures to a .sig file

#========================  Message Types ========================#
# Two more types of messages. No verifying and persisting is done

# 0x32 - ubirch standard sensor message (msgpack)
message_0x32 = protocol.message_chained(uuid, 0x32, [time.time(), "Hello World!", 1337])
response_0x32 = api.send(uuid, message_0x32)
print("Response 0x32: ({})\n {}".format(response_0x32.status_code, protocol.unpack_upp(response.content)))

# 0x53 - generic sensor message (json type key/value map)
message_0x53 = protocol.message_chained(uuid, 0x53, {"timestamp": time.time(), "message": "Hello World!", "foo": 1337})
response_0x53 = api.send(uuid, message_0x53)
print("Response 0x53: ({})\n {}".format(response_0x53.status_code, protocol.unpack_upp(response.content)))