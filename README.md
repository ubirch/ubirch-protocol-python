# ubirch-protocol for python

This is an implementation of the [ubirch-protocol](https://github.com/ubirch/ubirch-protocol)
for [Python 3](https://www.python.org/). Please see [ubirch-protocol](https://github.com/ubirch/ubirch-protocol)
for details.

## Usage

### Creating keypair and messages

```python
import ubirch
from ubirch.ubirch_protocol import CHAINED
from uuid import UUID
import binascii

# create a keystore for the device keypair
keystore = ubirch.KeyStore("device.jks", "keystore")

# create a UUID that identifies the device and load or create a keypair
uuid = UUID(hex="575A5601FD744F8EB6AEEF592CDEE12C")
if not keystore.exists_signing_key(uuid):
    keystore.create_ed25519_keypair(uuid)


# keys to sign the message
class ProtocolImpl(ubirch.Protocol):
    def _sign(self, message: bytes) -> bytes:
        return keystore.find_signing_key(uuid).sign(message)


proto = ProtocolImpl(CHAINED)
print(binascii.hexlify(proto.message(uuid.bytes, 0x00, [1, 2, 3])))
print(binascii.hexlify(proto.message(uuid.bytes, 0x00, [4, 5, 6])))
```
 
### Sending messages using the ubirch API

```python
# TODO
```

# License 

The protocol and its implementation are publicized under the [Apache License 2.0](LICENSE).