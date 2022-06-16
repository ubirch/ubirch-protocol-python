 

# Step By Step Example

*The code can be found in one place in `StepByStepExample.py` as well.*

Make sure to follow the setup steps in the [GettingStarted](GettingStarted.md) first. 

1. [Basic protocol](#basic-protocol)
2. [Key checks and key generation](#key-checks-and-key-generation)
3. [Using real data](#using-real-data)
4. [Verifying](#verifying)
   1. [Verify that the response really came from the backend](#verify-that-the-response-really-came-from-the-backend)
   2. [Verify that the UPP is correctly chained](#verify-that-the-upp-is-correctly-chained)
5. [UPP chaining](#upp-chaining)
6. [Message Types](#message-types)

### Basic protocol

As before we have to set the API and keystore credentials. Additionally the key type and environment variable is set.
```python
uuid = UUID(hex = "f5ded8a3-d462-41c4-a8dc-af3fd072a217" )
auth            = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

keystore_name     = "devices.jks"
keystore_password = "XXXXXXXXXXX"

key_type    = "ed25519"
env         = "demo"
```
- `keytype` defines the encryption algorithm, set to one of
  - `ed25519` default) [About Ed25519](https://ed25519.cr.yp.to/) 
  - `ecdsa` (improved efficiency) [About ECDSA](https://www.encryptionconsulting.com/education-center/what-is-ecdsa/)


- `env` is the UBIRCH backend environment (stage), set to one of
  - `prod` - production (default and recommended) 
  - `demo` - demonstration stage (for testing only)
  - `dev` - ubirch internal development stage (not reliable)
> **Note:** Set `env` to the environment where you registered the UUID

Instead of using a pre-made wrapper around protocol, api and keystore we implement it ourself!

This is best-practice to be accessible using the `ubirch.KeyStore`. You don't need to use this keystore and instead could plug in your own key management tool instead.

```python
import ubirch
from ubirch.ubirch_protocol import UBIRCH_PROTOCOL_TYPE_REG, UBIRCH_PROTOCOL_TYPE_BIN, UNPACKED_UPP_FIELD_PREV_SIG

import time, hashlib, binascii, ecdsa, ed25519
from uuid import UUID
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
            raise (ValueError("Signing Key is neither ed25519, nor ecdsa! It's: " + type(signing_key)))
```
`Proto` inherits the functions from `ubirch.protocol` and implements a `_sign()` function using the signing key found in the keystore.

```python
keystore = ubirch.KeyStore(keystore_name, keystore_password)

protocol = Proto(keystore, key_type)

api = ubirch.API(env=env)
api.set_authentication(uuid, auth)
```

1. Initialize a KeyStore and pass it to a `Proto` instance.
2. Initialize the API and make it remember your auth code

And finally packing data into an UPP and sending it:
```python
hashed_data = hashlib.sha512(b'{"T": 11.2, "H": 35.8, "S": "OK", "ts":"1652452008"}"').digest()

message_UPP = protocol.message_chained(uuid, ubirch.ubirch_protocol.UBIRCH_PROTOCOL_TYPE_BIN, hashed_data)
response = api.send(uuid, message_UPP)
print("Response: ({}) {}".format(response.status_code, binascii.hexlify(response.content).decode()))
```
1. Using SHA512 a serialized JSON object is hashed into 512 bits    
2. `protocol.message_chained()` calls the `_sign()` function implemented earlier
3. `UBIRCH_PROTOCOL_TYPE_BIN` is a constant which specifies the . This type resolves to `0x00`.
4. Then the UPP is sent to the ubirch backend and a cleartext response is printed

The 4 codeblocks above will be executed successfully if you have run the Getting Started instructions for this device before. 
Otherwise you will be prompted with the Error `Signing Key is neither ed25519, nor ecdsa!`

That's intended with this minimal implementation. The following will fix that

### Key checks and key generation

Add a check to the `__init__()` function that creates a keypair in case no keys are found.
```python
class Proto(ubirch.Protocol):
    def __init__(self, keystore, key_type):
        super().__init__()
        self.__ks = keystore
        
        if not self.__ks.exists_signing_key(uuid):
            if key_type == "ed25519":
                print("generating new keypair with ed25519 algorithm")

                self.__ks.create_ed25519_keypair(uuid)
            elif key_type == "ecdsa":
                print("generating new keypair with ecdsa algorithm")

                self.__ks.create_ecdsa_keypair(uuid)
            else:
                raise ValueError("unknown key type")
```
Add a key registration directly after the `api.set_authentication()` line.
```python
if not api.is_identity_registered(uuid):

    certificate = keystore.get_certificate(uuid)
    key_registration = protocol.message_signed(uuid, UBIRCH_PROTOCOL_TYPE_REG, certificate)

    response = api.register_identity(key_registration)
    print("Response: ({}) {}".format(response.status_code, response.content))
```
1. `api.is_identity_registered(uuid)` returns true if the public key is registered at the ubirch key service 
2. Get the certificate containing the keys from the Keystore
3. Create the registration message
4. `UBIRCH_PROTOCOL_TYPE_REG` is another constant in the [structure of UPP's](https://github.com/ubirch/ubirch-protocol/#basic-message-format). This type resolves to `0x01`.
5. Send the registration message with `api.register_identity()`

### Using real data

Until now the data to be sent is hardcoded as 
```python
hashed_data = hashlib.sha512(b'{"T": 11.2, "H": 35.8, "S": "OK", "ts":"1652452008"}"').digest()
```
Instead of that we 'receive' some data in an object / JSON format. 
The data should be sent to your own backend here as well, as ubirch only handles hashes of data.
```python
data = {
  "timestamp": int(time.time()),
  "temperature": 11.2,
  "humidity": 35.8,
  "status": "OK" 
}
```

A timestamp is included in the data to ensure a unique hash.

```python
serialized = json.dumps(data, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode()
```
Serializing a JSON object this way sorts the keys alphabetically and doesn't convert special characters to ascii.

E.g. `b'{"humidity":35.8,"status":"OK","temperature":11.2,"timestamp":1655286793}'`

This ensures determinism when creating the hash.

```python
hashed_data = hashlib.sha512(serialized).digest()
print("Message hash: {}".format(binascii.b2a_base64(hashed_data).decode().rstrip("\n")))

message_UPP = protocol.message_chained(uuid, ubirch.ubirch_protocol.UBIRCH_PROTOCOL_TYPE_BIN, hashed_data)
response = api.send(uuid, message_UPP)
print("Response: ({}) {}".format(response.status_code, binascii.hexlify(response.content).decode()))
```

1. Hash the message using SHA512
2. Create a new chained protocol message with the message hash
3. `UBIRCH_PROTOCOL_TYPE_BIN` is the type-code of a normal binary message. Here is resolves to `x00`
4. Send the created UPP to the ubirch backend

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
UBIRCH_UUIDS = {
    "dev": UUID(hex="9d3c78ff-22f3-4441-a5d1-85c636d486ff"),
    "demo": UUID(hex="07104235-1892-4020-9042-00003c94b60b"),
    "prod": UUID(hex="10b2e1a4-56b3-4fff-9ada-cc8c20f93016")
}

if protocol.verify_signature(UBIRCH_UUIDS[self.env], response.content) == True:
    print("Backend response signature successfully verified!")
else:
    raise Exception("Backend response signature verification FAILED!")
```
1. `UBIRCH_UUIDS[self.env]` returns the UUID of the selected backend stage 
2. `protocol.verify_signature()` parses the response-UPP and calls the `_verify()` function implemented earlier


#### Verify that the UPP is correctly chained

The field `SIGNATURE` ([structure of UPP's](https://github.com/ubirch/ubirch-protocol/#basic-message-format)) in the response-UPP from the server has to be the same as the sent UPPs signature.

```python
unpacked = protocol.unpack_upp(response.content)
signature_index = protocol.get_unpacked_index(unpacked[0], UNPACKED_UPP_FIELD_PREV_SIG)

previousSignatureInUPP = unpacked[signature_index]

_, signatureOfCurrentUPP = protocol.upp_msgpack_split_signature(currentUPP)

if signatureOfCurrentUPP == previousSignatureInUPP:
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
    def __init__(self, keystore, key_type):
        
        ...

        self.load(uuid)
        
    ...

    def persist(self, uuid: UUID):
        signatures = self.get_saved_signatures()
        with open(uuid.hex + ".sig", "wb") as f:
            pickle.dump(signatures, f)
        
    def load(self, uuid: UUID):
        try:
            with open(uuid.hex + ".sig", "rb") as f:
                signatures = pickle.load(f)
                print("Loaded {} known signatures".format(len(signatures)))
                self.set_saved_signatures(signatures)
        except FileNotFoundError:
            print("No existing saved signatures")
            pass

```
`persist()` needs to be called after sending an UPP. It will save the last signatures to a file similar to `80a80c6e4a7b46d4977b08efad0d1be2.sig`

`load()` is called at the end of `__init__(...)`

So append this somewhere after the call to `protocol.message_signed(...)`.

```python
protocol.persist(uuid)
```

### Message Types

When creating a message you already used the binary message and key registration message types.

`UBIRCH_PROTOCOL_TYPE_BIN` and `UBIRCH_PROTOCOL_TYPE_REG` earlier. These resolve to `0x00` and `0x01`.

There are more types for messages depending on the payload you want to send.

Refer to the [Payload Types](https://github.com/ubirch/ubirch-protocol#basic-message-format)
to see the different hex labels. 

Here are two more types of messages. No verifying and persisting is done.

`0x32` - ubirch standard sensor message (msgpack):

```python
message_0x32 = protocol.message_chained(uuid, 0x32, [time.time(), "Hello World!", 1337])
response_0x32 = api.send(message_0x32)

print("Response 0x32: ({}) {}".format(response_0x32.status_code, response_0x32.content))
```

`0x53` - generic sensor message (json type key/value map):

```python
message_0x53 = protocol.message_chained(uuid, 0x53, {"timestamp": time.time(), "message": "Hello World!", "foo": 1337})
response_0x53 = api.send(message_0x53)

print("Response 0x53: ({}) {}".format(response_0x53.status_code, response_0x53.content))

```





 


