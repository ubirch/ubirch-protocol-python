##
# @file GettingStarted.py
# Code accompanying the getting started guide at https://developer.ubirch.com/ubirch-protocol-python/GettingStarted.html

import time
from uuid import UUID

import ubirch
from UbirchWrapper import UbirchWrapper

#== 'Receive' data ==#
data = {
    "timestamp": int(time.time()),
    "temp": 11.2,
    "hum": 35.8,
    "stat": "OK"
}
# Include a timestamp in the JSON data message to ensure a unique hash.
# todo >> send data message to your backend, preferably encrypted, here <<


#== Setup Variables ==#
uuid = UUID(hex = "f5ded8a3-d462-41c4-a8dc-af3fd072a217" )
auth            = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

keystore_name     = "devices.jks"
keystore_password = "keystore"

#== Set up all parts of the Ubirch solution ==#

# Create a UbirchClient Object from the protocol wrapper with default demo environment
# You could use your own Key management tool instead.
# When called with parameters 'keystore_name' and 'keystore_password' it directly creates the components
#   Keystore, Protocol and API while initializing.
client = UbirchClient(uuid, auth, keystore_name=keystore_name, keystore_password=keystore_password)

# Check if the public key is registered at the Ubirch key service and register it if necessary
client.checkRegisterPubkey()

#== Create and send a Ubirch protocol packet ==#
# create a chained UPP message that contains a hash of the data
currentUPP = client.createUPP(data)

# send the message to the Ubirch authentication service
response = client.api.send(uuid, currentUPP)
client.handleMessageResponse(response)

#== Optional verification steps ==#

# catch any errors that could have come up and verify that the response came from the backend
client.verifyResponseSender(response)

# unpack the received upp to get its previous signature
previousSignatureInUPP = client.extractPreviousSignature(response)

# compare response signature with the sent UPP's signature
client.assertSignatureCorrect(previousSignatureInUPP)

# the handle, verification and assert functions raise Errors on any kind of error - save to assume success
print("Successfully sent the UPP and verified the response!")

# save last signatures
client.protocol.persist(uuid)
