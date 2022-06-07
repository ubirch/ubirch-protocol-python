##
# @file StepByStepExample.py
# Code accompanying the step by step guide

import time, hashlib, binascii
from uuid import UUID

import ubirch
from ubirch.ubirch_protocol import UBIRCH_PROTOCOL_TYPE_REG, UBIRCH_PROTOCOL_TYPE_BIN, UNPACKED_UPP_FIELD_PREV_SIG
from UbirchWrapper import UbirchClient, Proto, logger

#======================== 'Receive' data ========================#
data = {
    "timestamp": int(time.time()),
    "temp": 11.2,
    "hum": 35.8,
    "stat": "OK"
}
# Include a timestamp in the JSON data message to ensure a unique hash.
logger.info("Created an example data message: %s" % str(data))
# todo >> send data message to your backend, preferably encrypted, here <<

#======================== Setup Variables ========================#
uuid = UUID(hex = "80a80c6e-4a7b-46d4-977b-08efad0d1be2" )  # f5ded8a3-d462-41c4-a8dc-af3fd072a217
auth            = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"    # xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

keystore_name     = "devices.jks"
keystore_password = "keystore"    # 'XXXXXXXXXXX'

key_type    = "ed25519" # keytype can be 'ed25519' or 'ecdsa'
env         = "demo"    # env can be 'demo', 'prod' or 'dev'

#========== Setting up all parts of the Ubirch solution ==========#
client = UbirchClient(uuid, auth, key_type=key_type, env=env)
# create a UbirchClient Object from the protocol wrapper

client.keystore = ubirch.KeyStore(keystore_name, keystore_password)
# create a keystore for the device
# you could use your own key management tool instead

client.protocol = Proto(client.keystore, uuid, env, key_type=key_type)
# create an instance of the protocol with signature saving

client.api = ubirch.API(env=env)
client.api.set_authentication(uuid, auth)
# create an instance of the UBIRCH API and set the auth token

if not client.api.is_identity_registered(uuid):
    # check if the public key is registered at the ubirch key service and register it if necessary

    certificate = client.keystore.get_certificate(uuid)
    key_registration = client.protocol.message_signed(uuid, UBIRCH_PROTOCOL_TYPE_REG, certificate)
    # get the certificate and create the registration message

    response = client.api.register_identity(key_registration)
    client.handleRegistrationResponse(response)
    # send the registration message and catch any errors that could have come up


#=========== Create and send a Ubirch protocol packet ==========#
serialized = client.serializeMessage(data)    # todo = could be expanded
# Create a compact rendering of the message to ensure determinism when creating the hash
# Serializes a JSON object to bytes like this '{"T": 11.2, "H": 35.8, "S": "OK", "ts":"1652452008"}'

hashed_data = hashlib.sha512(serialized).digest()
# Hash the message using SHA512

logger.info("message hash: {}".format(binascii.b2a_base64(hashed_data).decode().rstrip("\n")))

currentUPP = client.protocol.message_chained(uuid, ubirch.ubirch_protocol.UBIRCH_PROTOCOL_TYPE_BIN, hashed_data)
# Create a new chained protocol message with the message hash
# UBIRCH_PROTOCOL_TYPE_BIN is the type-code of a normal binary message: '0x00'

logger.info("Created UPP: %s" % str(currentUPP.hex()))

response = client.api.send(uuid, currentUPP)
# send the message to the Ubirch authentication service

client.handleMessageResponse(response) # todo = could be expanded
# Catch any errors that could have come up

#== Optional verification steps ==#
client.verifyResponseSender(response) # todo = could be expanded
# Verify that the response came from the backend

signatureOfCurrentUPP = client.extractCurrentSignature(currentUPP) # todo = explain how UPP is constructed
# Get the UPP's signature for verification later

unpacked = client.protocol.unpack_upp(response.content)
signature_index = client.protocol.get_unpacked_index(unpacked[0], UNPACKED_UPP_FIELD_PREV_SIG)
previousSignatureInUPP = unpacked[signature_index] # todo = explain how UPP is constructed
# unpack the received upp to get its previous signature

client.assertSignatureCorrect(previousSignatureInUPP, signatureOfCurrentUPP) # todo = could be expanded
# compare response signature with the sent UPP's signature

print("Successfully sent the UPP and verified the response!")
# the handle, verification and assert functions raise Errors on any kind of error - save to assume success

client.protocol.persist(uuid)
# save last signatures to a .sig file
