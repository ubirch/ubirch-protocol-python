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
  
### Creating keypair and messages

```python
import ubirch
from ubirch.ubirch_protocol import CHAINED
from uuid import UUID
import binascii

# create a keystore for the device keypair
keystore = ubirch.KeyStore("demo-device.jks", "keystore")

# create a UUID that identifies the device and load or create a keypair
uuid = UUID(hex="575A5601FD744F8EB6AEEF592CDEE12C")
if not keystore.exists_signing_key(uuid):
    keystore.create_ed25519_keypair(uuid)

# implement the _sign method on the ubirch.Protocol to use the just created
# keys to sign the message and add methods to save and load the last signature
class ProtocolImpl(ubirch.Protocol):
    def _sign(self, uuid: UUID, message: bytes) -> bytes:
        return keystore.find_signing_key(uuid).sign(message)        

proto = ProtocolImpl(CHAINED)
print(binascii.hexlify(proto.message_chained(uuid, 0x00, [1, 2, 3])))
print(binascii.hexlify(proto.message_chained(uuid, 0x00, [4, 5, 6])))
```
 
### Sending messages using the ubirch API

Please see [test-protocol.py](examples/test-protocol.py) for a comprehensive example, how to create a device and
send data. Below is a snipped that will send two chained messages, using the generic key/value payload.

You will need an authentication token for the ubirch backend. Feel free to [contact us](https://ubirch.com), 
self on-bording is on it's way!

```python
import ubirch
import uuid
import binascii
from datetime import datetime

uuid = uuid.uuid4()
proto = ubirch.Protocol()
api = ubirch.API()

# message 1
msg = proto.message_chained(uuid, 0x53, {'ts': int(datetime.utcnow().timestamp()), 'v': 99})

print(binascii.hexlify(msg))
r = api.send(msg)
print("{}: {}".format(r.status_code, r.content))

# message 2 (chained to message 1)
msg = proto.message_chained(uuid, 0x53, {"ts": int(datetime.utcnow().timestamp()), "v": 100})
print(binascii.hexlify(msg))
r = api.send(msg)
print("{}: {}".format(r.status_code, r.content))
```

### Verification of received message

```python
import ubirch
import hashlib

from ed25519 import VerifyingKey
from uuid import UUID
from ubirch.ubirch_protocol import SIGNED

remote_uuid = UUID(hex="6eac4d0b-16e6-4508-8c46-22e7451ea5a1")
remote_vk = VerifyingKey("b12a906051f102881bbb487ee8264aa05d8d0fcc51218f2a47f562ceb9b0d068", encoding='hex')
# a random signed ubirch-protocol message
keystore = ubirch.KeyStore("demo-device.jks", "keystore")
keystore.insert_ed25519_verifying_key(remote_uuid, remote_vk)


class ProtocolImpl(ubirch.Protocol):
    def _verify(self, uuid: UUID, message: bytes, signature: bytes) -> dict:
        hash = hashlib.sha512(message).digest()
        return keystore.find_verifying_key(uuid).verify(signature, hash)


proto = ProtocolImpl(SIGNED)

message = bytes.fromhex(
    "9512b06eac4d0b16e645088c4622e7451ea5a1ccef01da0040578a5b22ceb3e1"
    "d0d0f8947c098010133b44d3b1d2ab398758ffed11507b607ed37dbbe006f645"
    "f0ed0fdbeb1b48bb50fd71d832340ce024d5a0e21c0ebc8e0e")
print(proto.message_verify(message))
```
> TBD

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
pip install -r requirements.txt
python3 examples/test-protocol.py
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
python3 -m unittest discover
``` 
# License 

The protocol and its implementation are publicized under the [Apache License 2.0](LICENSE).