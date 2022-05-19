import time
from uuid import UUID

import ubirch
from UbirchWrapper import UbirchClient

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
uuid = UUID(hex = "80a80c6e-4a7b-46d4-977b-08efad0d1be2" )  # f5ded8a3-d462-41c4-a8dc-af3fd072a217
auth            = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"    # xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

keystore_name     = "devices.jks"
keystore_password = "keystore"

#== Set up all parts of the Ubirch solution ==#
client = UbirchClient(uuid, auth, keystore_name=keystore_name, keystore_password=keystore_password)
# Create a UbirchClient Object from the protocol wrapper with default demo environment
# You could use your own Key management tool instead.
# When called with parameters 'keystore_name' and 'keystore_password' it directly creates the components
#   Keystore, Protocol and API while initializing.

client.checkRegisterPubkey()
# Check if the public key is registered at the Ubirch key service and register it if necessary

#== Create and send a Ubirch protocol packet ==#
currentUPP = client.createUPP(data)
# create a chained UPP message that contains a hash of the data

response = client.api.send(uuid, currentUPP)
# send the message to the Ubirch authentication service

client.handleMessageResponse(response)

#== Optional verification steps ==#
client.verifyResponseSender(response)
# catch any errors that could have come up and verify that the response came from the backend

previousSignatureInUPP = client.extractPreviousSignature(response)
# unpack the received upp to get its previous signature

client.assertSignatureCorrect(previousSignatureInUPP)
# compare response signature with the sent UPP's signature

print("Successfully sent the UPP and verified the response!")
# the handle, verification and assert functions raise Errors on any kind of error - save to assume success

client.protocol.persist(uuid)
# save last signatures
