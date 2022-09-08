# ubirch-protocol for python

This is an implementation of the [ubirch-protocol](https://github.com/ubirch/ubirch-protocol)
for [Python 3](https://www.python.org/). Please see [ubirch-protocol](https://github.com/ubirch/ubirch-protocol)
for details.

The library consists of three parts which can be used individually:

* `ubirch.API` - a python layer covering the ubirch backend REST API
* `ubirch.Protocol` - the protocol compiler which packages messages and handles signing and verification
* `ubirch.KeyStore` - a simple key store based on [pyjks](https://pypi.org/project/pyjks/) to store keys and certificates

> the [ubirch](https://ubirch.com) protocol uses the [Ed25519](https://ed25519.cr.yp.to/) signature scheme by default.
 
## Usage

Install the library: `pip install ubirch-protocol`
  
### Creating keypair and messages

```python
import ubirch
from uuid import UUID
import binascii

# create a keystore for the device keypair
keystore = ubirch.KeyStore("demo-device.jks", "keystore")

# create a UUID that identifies the device and load or create a keypair
uuid = UUID(hex="575A5601FD744F8EB6AEEF592CDEE12C")
if not keystore.exists_signing_key(uuid):
    keystore.create_ed25519_keypair(uuid)

# implement the _sign method of the ubirch.Protocol to use the just created keys to sign the message
class ProtocolImpl(ubirch.Protocol):
    def _sign(self, uuid: UUID, message: bytes) -> bytes:
        return keystore.find_signing_key(uuid).sign(message)        

# create an instance of the ubirch protocol
proto = ProtocolImpl()

# create ubirch protocol messages
print(binascii.hexlify(proto.message_chained(uuid, 0x00, [1, 2, 3])))
print(binascii.hexlify(proto.message_chained(uuid, 0x00, [4, 5, 6])))
```
 
### Sending messages using the ubirch API

Please see [test-protocol.py](examples/test-protocol.py) for a comprehensive example, how to create a device and
send data. Below is a snipped that will send two chained messages, using a generic key/value payload.

You will need a password for the ubirch backend. Go to https://console.demo.ubirch.com to register your UUID 
under `Things`. Then click on your device and copy the password from the `apiConfig`-field.

```python
import ubirch
from uuid import UUID
import binascii
from datetime import datetime

# create a keystore for the device key pair
keystore = ubirch.KeyStore("demo-device.jks", "keystore")

# create a UUID that identifies the device and load or create a key pair
uuid = UUID(hex="575A5601FD744F8EB6AEEF592CDEE12C")
if not keystore.exists_signing_key(uuid):
    keystore.create_ed25519_keypair(uuid)


# implement the _sign method of the ubirch.Protocol
class ProtocolImpl(ubirch.Protocol):
    def _sign(self, _uuid: UUID, message: bytes) -> bytes:
        return keystore.find_signing_key(uuid).sign(message)


# create an instance of the ubirch protocol
proto = ProtocolImpl()

# create an instance of the ubirch API and set the password
api = ubirch.API()
api.set_authentication(uuid, "<< password for the ubirch backend >>")  # register your UUID at https://console.demo.ubirch.com and retrieve your password

# message 1
msg = proto.message_chained(uuid, 0x53, {'ts': int(datetime.utcnow().timestamp()), 'v': 99})
print(binascii.hexlify(msg))
# send message to ubirch backend
r = api.send(uuid, msg)
print("{}: {}".format(r.status_code, r.content))

# message 2 (chained to message 1)
msg = proto.message_chained(uuid, 0x53, {"ts": int(datetime.utcnow().timestamp()), "v": 100})
print(binascii.hexlify(msg))
# send message to ubirch backend
r = api.send(uuid, msg)
print("{}: {}".format(r.status_code, r.content))
```

### Verification of received message

```python
import ubirch
from ed25519 import VerifyingKey, BadSignatureError
from uuid import UUID

remote_uuid = UUID(hex="9d3c78ff22f34441a5d185c636d486ff")
remote_vk = VerifyingKey("a2403b92bc9add365b3cd12ff120d020647f84ea6983f98bc4c87e0f4be8cd66", encoding='hex')

# create a keystore and insert the verifying key
keystore = ubirch.KeyStore("demo-device.jks", "keystore")
keystore.insert_ed25519_verifying_key(remote_uuid, remote_vk)

# implement the _verify method of the ubirch.Protocol
class ProtocolImpl(ubirch.Protocol):
    def _verify(self, uuid: UUID, message: bytes, signature: bytes) -> dict:
        return keystore.find_verifying_key(uuid).verify(signature, message)

# create an instance of the ubirch protocol
proto = ProtocolImpl()

message = bytes.fromhex(
    "9623c4109d3c78ff22f34441a5d185c636d486ffc440a5b371acdfc8495790ee86802399585da50401b0d3c87f60946719338eb0283d36c0bac9b8a6a75a5385342e62932335da988b97c0ec211556db082e9f8478070081a76d657373616765bf796f7572207265717565737420686173206265656e207375626d6974746564c440c8529623a4c2335f7a8ae1eeea655768d2e9a0df141f481ced557c9dac7216e8f64ca9f6970fc6c1096ed49bcc6f7fa77d8f85d05bff5e1301588597edc9770e")

# verify the message (throws an exception if the message could not be verified)
try:
    print(proto.message_verify(message))
    print("verification successful!")
except BadSignatureError as e:
    print("ERROR: verification failed!")
```

### Existing keys

In case you create a key pair from our demo website, use the following code to insert it into the key store:

```python
import ubirch
import ed25519
import uuid

hwDeviceId = uuid.uuid4()
keystore = ubirch.KeyStore("demo-device.jks", "keystore")
key_encoded = input("paste the encoded private key here:")
sk = ed25519.SigningKey(key_encoded, encoding='hex')
vk = sk.get_verifying_key() 

keystore.insert_ed25519_keypair(hwDeviceId, vk, sk)
```

### Running the example

```bash
python3 -m venv venv3
. venv3/bin/activate
pip install -r requirements.txt
pip install ubirch-protocol
PYTHONPATH=. python3 examples/test-protocol.py
```

At the first launch the script generates a random UUID for your device and you will be asked
about the authentication token and the device group. You can safely ignore the device group, just press Enter.
The script creates a file `demo-device.ini` which is loaded upon running the script again. If
you need to change anything edit that file.

The script goes through a number of steps:

1. checks the existence of the device and deletes the device if it exists
2. registers the device with the backend
3. generates a new identity for that device and stores it in the key store
4. registers the new identity with the backend
5. sends two consecutive chained messages to the backend


### Testing

Unit tests are added to test the functionality of all objects provided in this library.

```bash
pip install -r requirements.test.txt
python3 -m pytest tests
``` 
# License 

The protocol and its implementation are publicized under the [Apache License 2.0](LICENSE).

