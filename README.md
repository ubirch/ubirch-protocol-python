# ubirch-protocol for python

This is an implementation of the [ubirch-protocol](https://github.com/ubirch/ubirch-protocol)
for [Python 3](https://www.python.org/). Please see [ubirch-protocol](https://github.com/ubirch/ubirch-protocol)
for details.

## Usage

### Creating keypair and messages

```python
from ubirch import UbirchKeyStore, UbirchProtocol
from ubirch.ubirch_protocol import CHAINED
from uuid import UUID
import binascii

# create a keystore for the device keypair
keystore = UbirchKeyStore("device.jks", "keystore")

# create a UUID that identifies the device and load or create a keypair
uuid = UUID(hex="575A5601FD744F8EB6AEEF592CDEE12C")
if not keystore.exists_signing_key(uuid):
    keystore.create_ed25519_keypair(uuid)

# implement the _sign method on the UbirchProtocol to use the just created
# keys to sign the message
class Proto(UbirchProtocol):
    def _sign(self, message: bytes) -> bytes:
        return keystore.find_signing_key(uuid).sign(message)


proto = Proto(CHAINED)
print(binascii.hexlify(proto.message(uuid.bytes, 0x00, [1, 2, 3])))
print(binascii.hexlify(proto.message(uuid.bytes, 0x00, [4, 5, 6])))
```
 
### Sending messages using the ubirch API

```python
# TODO
```