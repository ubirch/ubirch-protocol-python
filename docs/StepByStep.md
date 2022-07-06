
# Step By Step Example


Make sure to follow the setup steps in the [GettingStarted](GettingStarted.md) first. 

1. [Basic protocol](#basic-protocol)
2. [Key checks and key generation](#key-checks-and-key-generation)
3. [Using real data](#using-real-data)
4. [Verifying](#verifying)
   - [Verify that the response really came from the backend](#verify-that-the-response-really-came-from-the-backend)
   - [Verify that the UPP is correctly chained](#verify-that-the-upp-is-correctly-chained)
5. [UPP chaining](#upp-chaining)
6. [Message Types](#message-types)

*The code can be found in [`StepByStepExample.py`](../examples/StepByStepExample.py) as well.*

*Run it from your command prompt using `$ python examples/StepByStepExample.py` or copy-paste one codeblock after another to build the implementation **step by step**.*

### Basic protocol
Please follow the steps until the end to build a complete protocol.

As before we have to set the API and keystore credentials. Additionally the key type and environment variable is set.
```python
from uuid import UUID

uuid = UUID(hex = "f5ded8a3-d462-41c4-a8dc-af3fd072a217" )
auth            = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

keystore_name     = "devices.jks"
keystore_password = "XXXXXXXXXXX"

key_type    = "ed25519"
env = "demo"
```
- `keytype` defines the encryption algorithm, set to one of
  - `ed25519` (default) using the [Ed25519 curve](https://en.wikipedia.org/wiki/Curve25519) 
  - `ecdsa` using the [ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm) Algorithm
  

- `environment` is the Ubirch backend environment (stage), set to the environment where you registered the UUID
  - `prod` - production (default and recommended) 
  - `demo` - demonstration stage (for testing only)
  - `dev` - Ubirch internal development stage (not reliable)

> Instead of using the example [`UbirchWrapper.py`](../examples/UbirchWrapper.py) as in [Getting Started](GettingStarted.md), this guide weaves `ubirch.KeyStore` together with the `ubirch.Protocol`.
>
> But you can also use your own key management tool instead!

The best-practice to do this is to extend the `ubirch.Protocol` with a `_sign()` function that uses the signing key found in the keystore.

```python
import ubirch
from ubirch.ubirch_protocol import UBIRCH_PROTOCOL_TYPE_REG, UBIRCH_PROTOCOL_TYPE_BIN, UNPACKED_UPP_FIELD_PREV_SIG

from ubirch_keys_and_uuids import UBIRCH_UUIDS, UBIRCH_PUBKEYS_EC, UBIRCH_PUBKEYS_ED

import time, json, pickle, hashlib, binascii, ecdsa, ed25519
from requests import codes, Response

 
class Proto(ubirch.Protocol):
    def __init__(self, keystore, key_type):
        super().__init__()
        self.__ks = keystore

    def _sign(self, uuid, message):
        signing_key = self.__ks.find_signing_key(uuid)

        if isinstance(signing_key, ecdsa.SigningKey):
            # no hashing required here
            return signing_key.sign(message)

        elif isinstance(signing_key, ed25519.SigningKey):
            hashed_message = hashlib.sha512(message).digest()
            return signing_key.sign(hashed_message)

        else:
            raise (ValueError("Signing Key is neither ed25519, nor ecdsa! It's: " + str(type(signing_key))))

        
keystore = ubirch.KeyStore(keystore_name, keystore_password)

protocol = Proto(keystore, key_type)

api = ubirch.API(env=env)
api.set_authentication(uuid, auth)
```

1. Initialize a KeyStore and pass it to a `Proto` instance.
2. Initialize the API and make it remember your auth code

Then lets say we 'receive' some data in an object / JSON format. 
The data should be sent to your own backend here as well, as Ubirch only handles hashes of data.

```python
import time

data = {
"timestamp": int(time.time()),
"temperature": 11.2,
"humidity": 35.8,
"status": "OK"
}
```

A timestamp is included in the data to ensure a unique hash.

Finally packing data into a UPP and sending it:
```python
serialized = json.dumps(data, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode()

hashed_data = hashlib.sha512(serialized).digest()
print("Message hash: {}".format(binascii.b2a_base64(hashed_data).decode().rstrip("\n")))

message_UPP = protocol.message_chained(uuid, ubirch.ubirch_protocol.UBIRCH_PROTOCOL_TYPE_BIN, hashed_data)
response = api.send(uuid, message_UPP)
print("Response: ({}) {}".format(response.status_code, binascii.hexlify(response.content).decode()))
```
1. Serialize the JSON data object to bytes
   - Sorts the keys alphabetically and doesn't convert special characters to ascii
   - This ensures determinism when creating the hash. For example:
   - `b'{"humidity":35.8,"status":"OK","temperature":11.2,"timestamp":1655286793}'`
2. Hash the message using SHA512 into 512 bits    
3. Create a new chained protocol message with the message hash 
   - `protocol.message_chained()` calls the `_sign()` function implemented earlier
4. `UBIRCH_PROTOCOL_TYPE_BIN` is the type-code of a standard binary message. Here is resolves to `x00`
5. Send the created UPP to the Ubirch backend

The codeblocks above will be executed successfully if you have run the Getting Started instructions for this device before. 
Otherwise you will be prompted with the Error 

`ValueError: Signing Key is neither ed25519, nor ecdsa! It's: <class 'NoneType'>`

That's because there still are missing functionalities in the basic protocol. The following will fix that.

### Key checks and key generation
Add a check to the `__init__()` function depending on the key type.
It creates a keypair in case no keys are found and removes invalid key entries.


```python
class Proto(ubirch.Protocol):
    def __init__(self, keystore: ubirch.KeyStore, key_type: str):
        super().__init__()
        self.__ks = keystore

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
```

Add a check for key registration directly after the `api.set_authentication()` line:
```python
...

api.set_authentication(uuid, auth)

if not api.is_identity_registered(uuid):

    certificate = keystore.get_certificate(uuid)
    key_registration = protocol.message_signed(uuid, UBIRCH_PROTOCOL_TYPE_REG, certificate)

    response = api.register_identity(key_registration)
    print("Response: ({}) {}".format(response.status_code, response.content))
```
1. `api.is_identity_registered(uuid)` returns true if the public key is registered at the Ubirch key service 
2. Get the certificate containing the keys from the Keystore
3. Create the registration message
4. `UBIRCH_PROTOCOL_TYPE_REG` is another constant in the [structure of UPP's](https://github.com/ubirch/ubirch-protocol/#basic-message-format). This type resolves to `0x01`.
5. Send the registration message with `api.register_identity()`

Now running the script will add a public key to the thing in the Ubirch console.

### Verifying

#### Verify that the response really came from the backend

Add a `_verify()` function that verifies a signature against contents of a message.

```python
class Proto(ubirch.Protocol):

...

    def _verify(self, uuid: UUID, message: bytes, signature: bytes):
        verifying_key = self.__ks.find_verifying_key(uuid)

        if isinstance(verifying_key, ecdsa.VerifyingKey):
            # no hashing required here
            return verifying_key.verify(signature, message)

        elif isinstance(verifying_key, ed25519.VerifyingKey):
            hashed_message = hashlib.sha512(message).digest()
            return verifying_key.verify(signature, hashed_message)

        else:
            raise (ValueError("Verifying Key is neither ed25519, nor ecdsa! It's: " + type(verifying_key)))

        return verifying_key.verify(signature, final_message)
```

And append this to the script's end

```python
if protocol.verfiy_signature(UBIRCH_UUIDS[env], response.content) == True:
    print("Backend response signature successfully verified!")
else:
    raise Exception("Backend response signature verification FAILED!")
```
1. `UBIRCH_UUIDS[self.env]` returns the UUID of the selected backend stage 
2. `protocol.verify_signature()` parses the response-UPP and calls the `_verify()` function implemented earlier


#### Verify that the UPP is correctly chained

The field `SIGNATURE` ([structure of UPP's](https://github.com/ubirch/ubirch-protocol/#basic-message-format)) in the response-UPP from the server has to be the same as the sent UPPs signature.
To assure that append this codeblock at the end: 

```python
unpacked = protocol.unpack_upp(response.content)
signature_index = protocol.get_unpacked_index(unpacked[0], UNPACKED_UPP_FIELD_PREV_SIG)

previous_signature_in_UPP = unpacked[signature_index]

_, signature_message_UPP = protocol.upp_msgpack_split_signature(message_UPP)

if signature_message_UPP == previous_signature_in_UPP:
    print("Sent UPP is correctly chained! The previous signature in the response UPP is the same as the sent UPPs Signature")
else:
    raise Exception("The previous signature in the response UPP doesn't match the signature of our UPP!")
```
1. Unpack the received upp to get its previous signature
2. `_` is a throwaway variable for the message content in the UPP


### UPP chaining

To always include the last UPP's signature in a new UPP it is necessary to save that signature.

Is best practice to just save it into a file, because normally there is only one chain that is being continued. 

Now implement signature loading and persisting (saving) by modifying `__init__()` and adding two new methods. 

```python
class Proto(ubirch.Protocol):
    def __init__(self, keystore: ubirch.KeyStore, key_type: str):
        super().__init__()
        self.__ks = keystore
        self.load_saved_signatures(uuid)
        ...
    
    ...

    def persist_signatures(self, uuid: UUID):
        signatures = self.get_saved_signatures()
        with open(uuid.hex + ".sig", "wb") as f:
            pickle.dump(signatures, f)
        
    def load_saved_signatures(self, uuid: UUID):
        try:
            with open(uuid.hex + ".sig", "rb") as f:
                signatures = pickle.load(f)
                print("Loaded {} known signatures".format(len(signatures)))
                self.set_saved_signatures(signatures)
        except FileNotFoundError:
            print("No existing saved signatures")
            pass

```
`load_saved_signatures()` is called at the end of `__init__(...)`

`persist_sigatures()` needs to be called after sending an UPP. It will save the last signatures to a file similar to `80a80c6e4a7b46d4977b08efad0d1be2.sig`

So append this somewhere after the call to `protocol.message_chained(...)`.

```python
protocol.persist_signatures(uuid)
```

### Message Types

When creating a message you already used the binary message and key registration message types.

`UBIRCH_PROTOCOL_TYPE_BIN` and `UBIRCH_PROTOCOL_TYPE_REG` earlier. These resolve to `0x00` and `0x01`.

There are more types for messages depending on the payload you want to send.

Refer to the [Payload Types](https://github.com/ubirch/ubirch-protocol#basic-message-format)
to see the different hex labels. 

Here are two more types of messages. No verifying and persisting is done.

`0x32` - Ubirch standard sensor message (msgpack):

```python
message_0x32 = protocol.message_chained(uuid, 0x32, [time.time(), "Hello World!", 1337])
response_0x32 = api.send(uuid, message_0x32)

print("Response 0x32: ({})\n {}".format(response_0x32.status_code, binascii.hexlify(response_0x32.content).decode()))
```

`0x53` - generic sensor message (json type key/value map):

```python
message_0x53 = protocol.message_chained(uuid, 0x53, {"timestamp": time.time(), "message": "Hello World!", "foo": 1337})
response_0x53 = api.send(uuid, message_0x53)

print("Response 0x53: ({})\n {}".format(response_0x53.status_code, binascii.hexlify(response_0x53.content).decode()))
```

>**Note:** If you hardcode the `timestamp` value to for example `10` instead of `time.time()` and send it twice you will get an `409` error. 
>
> That is because Ubirch backend did not accept the UPP due to the hash being the same as in a already anchored UPP.