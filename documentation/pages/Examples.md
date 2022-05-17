@page examples Example Implementations
@tableofcontents

<!-- These markdown files are supposed to be read by doxygen, 
a software for generating documentation. So don't wonder about the @page, 
@ref - or similar statements. Please refer as well to the 
official documentation at developer.ubirch.com -->

Examples which can be found in `/examples/`.

They are commandline examples, implementing uBirch components, that can be experimented around without the need to write Python code.

Those tools aim to be useful when getting started and to provide an insight of how to use the components. All of them are commandline tools who have to be given API Credentials.


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

**Running the script**

`$ python example-client.py f5ded8a3-d462-41c4-a8dc-af3fd072a217 xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx demo`

The output should be similar to this:
```json
    ubirch.ubirch_ks WARNING  creating new key store: devices.jks
                root INFO     generating new keypair with ed25519 algorithm
    ubirch.ubirch_ks INFO     inserted new key pair for 80a80c6e4a7b46d4977b08efad0d1be2: 334b4ba6f14c2b4d1848eb0ddd04145e563364a7e69195420effd2130cee64b2
                root WARNING  no existing saved signatures
                root INFO     ubirch-protocol: device id: 80a80c6e-4a7b-46d4-977b-08efad0d1be2
   ubirch.ubirch_api DEBUG    is identity registered?: 80a80c6e-4a7b-46d4-977b-08efad0d1be2
urllib3.connectionpo DEBUG    Starting new HTTPS connection (1): key.demo.ubirch.com:443
urllib3.connectionpo DEBUG    https://key.demo.ubirch.com:443 "GET /api/keyService/v1/pubkey/current/hardwareId/80a80c6e-4a7b-46d4-977b-08efad0d1be2 HTTP/1.1" 200 None
   ubirch.ubirch_api DEBUG    200: b'[]'
   ubirch.ubirch_api DEBUG    register identity [msgpack]: b'9522c41080a80c6e4a7b46d4977b08efad0d1be20187a9616c676f726974686dab4543435f45443235353139a763726561746564ce627cc55faa68774465766963654964c41080a80c6e4a7b46d4977b08efad0d1be2a67075624b6579c420334b4ba6f14c2b4d1848eb0ddd04145e563364a7e69195420effd2130cee64b2a87075624b65794964c420334b4ba6f14c2b4d1848eb0ddd04145e563364a7e69195420effd2130cee64b2ad76616c69644e6f744166746572ce7548c85fae76616c69644e6f744265666f7265ce627cc55fc4400f51a22de0b3ef23b55667b86baeacad90c0d760f2e5c139528af5679dacda33e6867b9cdb16f24681b5a91764be8c10d76d06c58a39dc63d69162d0c5f10609'
urllib3.connectionpo DEBUG    Starting new HTTPS connection (1): key.demo.ubirch.com:443
urllib3.connectionpo DEBUG    https://key.demo.ubirch.com:443 "POST /api/keyService/v1/pubkey/mpack HTTP/1.1" 200 None
   ubirch.ubirch_api DEBUG    200: b'{"pubKeyInfo":{"algorithm":"ECC_ED25519","created":"2022-05-12T08:29:19.000Z","hwDeviceId":"80a80c6e-4a7b-46d4-977b-08efad0d1be2","pubKey":"M0tLpvFMK00YSOsN3QQUXlYzZKfmkZVCDv/SEwzuZLI=","pubKeyId":"M0tLpvFMK00YSOsN3QQUXlYzZKfmkZVCDv/SEwzuZLI=","validNotAfter":"2032-05-09T08:29:19.000Z","validNotBefore":"2022-05-12T08:29:19.000Z"},"signature":"0f51a22de0b3ef23b55667b86baeacad90c0d760f2e5c139528af5679dacda33e6867b9cdb16f24681b5a91764be8c10d76d06c58a39dc63d69162d0c5f10609"}'
                root INFO     80a80c6e-4a7b-46d4-977b-08efad0d1be2: public key registered
                root INFO     Created an example data message: {'id': '80a80c6e-4a7b-46d4-977b-08efad0d1be2', 'ts': 1652351361, 'data': '89'}
                root INFO     message hash: TVlp7rPSoYjU1t3Nnx1fZlZMJcOvaTLIgzsGi9pgZpwlg1nXctHbpxWUmnkxknWKj4s8kodp2RcgnLaakw9Pxw==
                root INFO     Created UPP: 9623c41080a80c6e4a7b46d4977b08efad0d1be2c4400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c4404d5969eeb3d2a188d4d6ddcd9f1d5f66564c25c3af6932c8833b068bda60669c258359d772d1dba715949a793192758a8f8b3c928769d917209cb69a930f4fc7c4404ff491724676d64f419e3229ade1d4c93bd7a8dd12a757275729d0132159cfcadf9c1c1fab03205ad483f5c17bc48fa6366eadeca534c90c5cb4c5989ebe8605
   ubirch.ubirch_api DEBUG    sending [msgpack]: b'9623c41080a80c6e4a7b46d4977b08efad0d1be2c4400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c4404d5969eeb3d2a188d4d6ddcd9f1d5f66564c25c3af6932c8833b068bda60669c258359d772d1dba715949a793192758a8f8b3c928769d917209cb69a930f4fc7c4404ff491724676d64f419e3229ade1d4c93bd7a8dd12a757275729d0132159cfcadf9c1c1fab03205ad483f5c17bc48fa6366eadeca534c90c5cb4c5989ebe8605'
urllib3.connectionpo DEBUG    Starting new HTTPS connection (1): niomon.demo.ubirch.com:443
urllib3.connectionpo DEBUG    https://niomon.demo.ubirch.com:443 "POST / HTTP/1.1" 200 187
   ubirch.ubirch_api DEBUG    200: b'\x96#\xc4\x10\x9d<x\xff"\xf3DA\xa5\xd1\x85\xc66\xd4\x86\xff\xc4@O\xf4\x91rFv\xd6OA\x9e2)\xad\xe1\xd4\xc9;\xd7\xa8\xdd\x12\xa7W\'W)\xd0\x13!Y\xcf\xca\xdf\x9c\x1c\x1f\xab\x03 Z\xd4\x83\xf5\xc1{\xc4\x8f\xa66n\xad\xec\xa54\xc9\x0c\\\xb4\xc5\x98\x9e\xbe\x86\x05\x00\xc4 ;\xa4u\xfd,\xeeL\xad\x9a\x11\x15J\xa0H\xef\xad\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc4@]k\\\xed\xd2Y\xf9\x1a\xa4\xe5\xc27l\x7fH\x07g4}w-\xe7E\xed\xd8\x91\xe5\x99R\x83\x8f{z\xb9PW\xe3\x84\xed\xd9\xfa\x84\x90\xa8\x04\x12\x19\n\x02\xe2fr\xe9\x87i\x93\xe0N\x1b\xdc\xfc\x8e\x80\x00'
                root INFO     UPP successfully sent. response: 9623c4109d3c78ff22f34441a5d185c636d486ffc4404ff491724676d64f419e3229ade1d4c93bd7a8dd12a757275729d0132159cfcadf9c1c1fab03205ad483f5c17bc48fa6366eadeca534c90c5cb4c5989ebe860500c4203ba475fd2cee4cad9a11154aa048efad00000000000000000000000000000000c4405d6b5cedd259f91aa4e5c2376c7f480767347d772de745edd891e59952838f7b7ab95057e384edd9fa8490a80412190a02e26672e9876993e04e1bdcfc8e8000
                root INFO     Backend response signature successfully verified!
                root INFO     Matching previous signature!
                root INFO     Successfully sent the UPP and verified the response!
```


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

### Test identity of the device
The [`test-identity.py`](test-identity.py) script tests registering and de-registering a public key of a device at the uBirch backend. To function it needs the following variables to be set using the environment:
```sh
export UBIRCH_UUID=<UUID>
export UBIRCH_AUTH=<ubirch-authorization-token>
export UBIRCH_ENV=[dev|demo|prod]
```
It uses `test-identity.jks` as a place to store/look for keypairs. The keystore-password can be read from the [script](test-identity.py) itself.
