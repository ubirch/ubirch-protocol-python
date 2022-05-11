@page examples Example Implementations
@tableofcontents

<!-- These markdown files are supposed to be read only by doxygen. 
So don't wonder about the @ref - or similar statements
Please refer to the official documentation -->

Examples which can be found in `/examples/`.

- [Example Implementations](#example-implementations)
  - [Sending data to the Simple Data Service](#sending-data-to-the-simple-data-service)
  - [Example uBirch client implementation](#example-ubirch-client-implementation)
  - [Test the complete protocol](#test-the-complete-protocol)
  - [Test identity of the device](#test-identity-of-the-device)

### Simple Data Service
The [`data-sender.py`](data-sender.py) example-script allows sending of data to the simple data service. This should only be used for demo purposes. Ubirch will not guarantee, to keep all data, which is sent to this endpoint.
```
$ python3 data-sender.py --help
usage: data-sender.py [-h] [--env ENV] UUID AUTH INPUT

Send some data to the uBirch Simple Data Service

positional arguments:
  UUID               UUID to work with; e.g.: 56bd9b85-6c6e-4a24-bf71-f2ac2de10183
  AUTH               uBirch device authentication token
  INPUT              data to be sent to the simple data service

optional arguments:
  -h, --help         show this help message and exit
  --env ENV, -e ENV  environment to operate in; dev, demo or prod (default: dev)

Note that the input data should follow this pattern: {"timestamp": TIMESTAMP, "uuid": "UUID", "msg_type": 0, "data": DATA, "hash": "UPP_HASH"}. For more information take a look at the EXAMPLES.md file.
```
###
### Example uBirch client
This is the same example as used in the [step by step guide](@ref StepByStep).

[`example-client.py`](example-client.py) implements a full example uBirch client. It generates a keypair if needed, registers it at the uBirch backend if it doesn't know it yet, creates and sends a UPP and handles/verfies the response from the uBirch backend. The used message format looks like this:
```
{
  "id": "UUID",
  "ts": TIMESTAMP,
  "data": "DATA"
}
```
It has two positional and one optional command line parameters.
```
usage: python3 example-client.py <UUID> <ubirch-auth-token> [ubirch-env]
```
- `UUID` is the UUID as hex-string like `f5ded8a3-d462-41c4-a8dc-af3fd072a217`
- `ubirch-auth-token` is the uBirch authentication token for the specified UUID, e.g.: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
- `ubirch-env` (optional) specifies the environment/stage to operator on. `dev`, `demo` or `prod` (default).
Keys are loaded from/stored to `demo-device.jks`. The keystore-password can be read from the [script](example-client.py) itself.

###
### Test the complete protocol
The [`test-protocol.py`](test-protocol.py) script sends a couple of UPPs to uBirch Niomon and verifies the backend response. It reads all information it needs interactively from the terminal. Once entered, all device information (UUID, ENV, AUTH TOKEN) are stored in a file called `demo-device.ini`. Devices keys are stored in `demo-device.jks` and the keystore-password can be read from the [script](test-protocol.py) itself. If no keys for the given UUID are found, the script will generated a keypair and stores it in the keystore file.


**copied from Readme:** At the first launch the script generates a random UUID for your device and you will be asked
about the authentication token and the device group. You can safely ignore the device group, just press Enter.
The script creates a file `demo-device.ini` which is loaded upon running the script again. If
you need to change anything edit that file.

The script goes through a number of steps:

1. checks the existence of the device and deletes the device if it exists
2. registers the device with the backend
3. generates a new identity for that device and stores it in the key store
4. registers the new identity with the backend
5. sends two consecutive chained messages to the backend

###
### Test identity of the device
The [`test-identity.py`](test-identity.py) script tests registering and de-registering a public key of a device at the uBirch backend. To function it needs the following variables to be set using the environment:
```sh
export UBIRCH_UUID=<UUID>
export UBIRCH_AUTH=<ubirch-authorization-token>
export UBIRCH_ENV=[dev|demo|prod]
```
It uses `test-identity.jks` as a place to store/look for keypairs. The keystore-password can be read from the [script](test-identity.py) itself.
