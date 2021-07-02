# uBirch-Protocol-Python Examples
This file documents how to use the examples provided alongside the [uBirch-Protocol-Python](https://github.com/ubirch/ubirch-protocol-python). Those examples aim to provide an insight of how to use the [ubirch-protocol](https://pypi.org/project/ubirch-protocol/) python library, which is implemented in the `/ubirch/` directory in this repository.

## Table of contents
- [uBirch-Protocol-Python Examples](#ubirch-protocol-python-examples)
  - [Table of contents](#table-of-contents)
  - [From measurement to blockchain-anchored UPP](#from-measurement-to-blockchain-anchored-upp)
    - [Setup](#setup)
    - [Generating and managing a keypair](#generating-and-managing-a-keypair)
    - [Registering a public key](#registering-a-public-key)
    - [Gathering Data](#gathering-data)
    - [Creating a UPP](#creating-a-upp)
    - [Sending a UPP](#sending-a-upp)
    - [Verifying a UPP](#verifying-a-upp)
    - [Examining a UPP](#examining-a-upp)
    - [Checking the anchoring status of an UPP](#checking-the-anchoring-status-of-an-upp)
    - [Verifying a measurement](#verifying-a-measurement)
  - [Sending data to the Simple Data Service](#sending-data-to-the-simple-data-service)
  - [Example uBirch client implementation](#example-ubirch-client-implementation)

## From measurement to blockchain-anchored UPP
The process needed to get a UPP to be anchored in the blockchain can be cut down into multiple steps.  For each of those steps there is an example in this directory, demonstrating how one could handle them. There also are examples showing a full example-client implementation.

0. [Setup](#setup)
1. [Gathering Data](#gathering-data)

### Setup
Before anything, you will need to do/get a couple of things:
- Choose a stage to work on
- Get a account for the uBirch-Console
  - https://console.prod.ubirch.com for the `prod` stage
  - https://console.demo.ubirch.com for the `demo` stage
  - https://console.dev.ubirch.com for the `dev` stage
- Get a UUID (can be generated randomly or on the basis of certain device properties like MAC-Addresses)
- Create a "Thing" at the uBirch-Console; remember/note down the used UUID and the generated Auth-Token

You should now have the following information at hand:
- The stage you want to work on (later referred to as `env`)
- The UUID of your device or "fake" device in this instance
- The authentication token (`auth token`) for the named UUID

The values used below are `f5ded8a3-d462-41c4-a8dc-af3fd072a217` for the UUID, `demo` for the env and
`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` for the auth token.

### Generating and managing a keypair
To create, or more precisely, to _sign_ a UPP, a device will need a keypair. This keypair consist of a private key (_signing key_) and public key (_verifying key_). The signing key is used to sign UPPs and the verifying key can be used by the uBirch backend to check if the signature is valid and belongs to the correct sender/signer. So logically, it doesn't matter who knows to verifying key, but the signing key must be kept secret all the time. In a real usecase, a device might store it in a TPM ([Trusted platform module](https://en.wikipedia.org/wiki/Trusted_Platform_Module)) or use other counter measures against an attacker reading the key from the device. For this demo, keypairs will be stored in a [JKS Keystore](https://en.wikipedia.org/wiki/Java_KeyStore) using the [`pyjks`](https://pypi.org/project/pyjks/) library. For that you will have to chose and remember a file path for that keystore and a password used to encrypt it. The process of actually generating the keypair is exlpained [bellow](#registering-a-public-key).

**NOTE** that losing access to the signing key, especially if it is already registered at the uBirch backend, will take away the ability to create and send any new UPPs from that device/UUID, since there is no way of creating a valid signature that would be accepted by the backend.

A keystore can be read out with the `keystore-dumper.py` script.

```
$ python keystore-dumper.py --help
usage: keystore-dumper.py [-h] [--show-sk SHOW_SIGNING_KET] KEYSTORE KEYSTORE_PASS

Dump the contents of a keystore (.jks)

positional arguments:
  KEYSTORE              keystore file path; e.g.: test.jks
  KEYSTORE_PASS         keystore password; e.g.: secret

optional arguments:
  -h, --help            show this help message and exit
  --show-sk SHOW_SIGNING_KET, -s SHOW_SIGNING_KET
                        enables/disables showing of signing keys; e.g.: true, false (default: False)
```
By default, only UUIDs und public keys (verifying keys) will be displayed. Displaying of private keys (signing keys) can be enabled by passing `-s true`.

### Registering a public key
To enable the uBirch backend to verify a UPP, it needs to know the corresponding verifying key. Therefore, the device needs to send this key to the backend before starting to send UPPs supposed to be verified and anchored. Registering a verifying key is also done by sending a special kind of UPP containing this key. This can be done by using two scripts:
```
upp-creator.py
upp-sender.py
```
Both of these scripts will be explained in more detail in [Creating a UPP](#creating-a-upp) and [Sending a UPP](#sending-a-upp). To generate a _Public Key Registration UPP_ this command can be used:
```
$ python upp-creator.py -t 1 --ks devices.jks --kspwd keystore --keyreg true --output keyreg_upp.bin f5ded8a3-d462-41c4-a8dc-af3fd072a217 none

2021-07-02 11:51:50,483                 root        init_keystore() INFO     No keys found for "f5ded8a3-d462-41c4-a8dc-af3fd072a217" in "devices.jks" - generating a keypair
2021-07-02 11:51:50,485     ubirch.ubirch_ks insert_ed25519_keypa() INFO     inserted new key pair for f5ded8a3d46241c4a8dcaf3fd072a217: e0264e7d9428149cef59ccecb8813b214d8f94c62e3e836d7546d3f8bd884a4c
2021-07-02 11:51:50,485                 root        init_keystore() INFO     Public/Verifying key for "f5ded8a3-d462-41c4-a8dc-af3fd072a217" [base64]: "4CZOfZQoFJzvWczsuIE7IU2PlMYuPoNtdUbT+L2ISkw="
2021-07-02 11:51:50,485                 root                 load() WARNING  no existing saved signatures
2021-07-02 11:51:50,485                 root      prepare_payload() INFO     UPP payload (sha512 hash of the data) [base64]: "q5Op6V1w7bBgJVEc6k4rgEf7fh3q9yRPwNPt9efLV9j7e5Ub3rPGtVJxSHh0nrGbkQPmSoNjXoiFx9Ph0PxWSQ=="
2021-07-02 11:51:50,485                 root           create_upp() INFO     Generating a key registration UPP for UUID "f5ded8a3-d462-41c4-a8dc-af3fd072a217"
2021-07-02 11:51:50,485                 root       show_store_upp() INFO     UPP [hex]: "9522c410f5ded8a3d46241c4a8dcaf3fd072a2170187a9616c676f726974686dab4543435f45443235353139a763726561746564ce60dec596aa68774465766963654964c410f5ded8a3d46241c4a8dcaf3fd072a216a67075624b6579c420e0264e7d9428149cef59ccecb8813b214d8f94c62e3e836d7546d3f8bd884a4ca87075624b65794964c420e0264e7d9428149cef59ccecb8813b214d8f94c62e3e836d7546d3f8bd884a4cad76616c69644e6f744166746572ce62bff916ae76616c69644e6f744265666f7265ce60dec596c440cadb70d30250a5a2dd2eb44b645e54b56387f228607fbf6f59a11493befa118f0e9c79da1f7d85ba5a4076c134f8b4aff04173adfc4b858ec491be2366988900"
2021-07-02 11:51:50,485                 root       show_store_upp() INFO     UPP written to "keyreg_upp.bin"
```
The generated key registration UPP has been saved to `keyreg_upp.bin`. Sending the UPP can be done like following (remember to put the correct value for the env of your choice):
```
$ python upp-sender.py --env demo --input keyreg_upp.bin --output response_upp.bin f5ded8a3-d462-41c4-a8dc-af3fd072a217 xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

2021-07-02 12:05:49,556                 root             read_upp() INFO     Reading the input UPP for "f5ded8a3-d462-41c4-a8dc-af3fd072a217" from "keyreg_upp.bin"
2021-07-02 12:05:49,556                 root      check_is_keyreg() INFO     The UPP is a key registration UPP - disabling identity registration check
2021-07-02 12:05:50,712                 root             send_upp() INFO     The key resgistration message for "f5ded8a3-d462-41c4-a8dc-af3fd072a217" was accepted
2021-07-02 12:05:50,712                 root             send_upp() INFO     b'{"pubKeyInfo":{"algorithm":"ECC_ED25519","created":"2021-06-27T13:12:46.000Z","hwDeviceId":"f5ded8a3-d462-41c4-a8dc-af3fd072a217","pubKey":"dsbKkw9HpsTvlLGgmiaYAM4M/ytFcySoF5UbfScffxg=","pubKeyId":"dsbKkw9HpsTvlLGgmiaYAM4M/ytFcySoF5UbfScffxg=","validNotAfter":"2022-06-27T13:12:46.000Z","validNotBefore":"2021-06-27T13:12:46.000Z"},"signature":"1e47255c7494fb54d5ab10897d53c1a38872e6a67af3d53e5ae49d6c190d0aaab70741a1af9b08793aaae82ea5a207402d5a15c563b859525e193a05f0a6510b"}'
```
After the command successfully completed there should be an entry in the `PublicKeys` tab of the device.

### Gathering Data
UPPs are usually used to anchor the hash of some kind of data. This data, in theory, can be everything. All examples below will use a simple string representing a JSON object like this for simplicity:
```json
{
    "ts": 1625163338,
    "T": 11.2,
    "H": 35.8,
    "S": "OK"
}
```
Translated to a hypothetical usecase this could be a measurement taken at `1625163338` (Unix-Timestamp), stating that the sensor measured `11.2 C` in temperature (`T`) and `35.8 %H` in humidity (`H`). The  status - `S` - is `'OK'`. There is no script for this step, since it can easily done by hand.

### Creating a UPP
After gathering some measurement data a UPP can be created. The won't contain the actual measurement data, but a hash of it. The script used to create UPPs in this example is `upp-creator.py`.
```
$ python3 upp-creator.py --help

usage: upp-creator.py [-h] [--version VERISON] [--type TYPE] [--ks KS] [--kspwd KSPWD] [--keyreg KEYREG] [--hash HASH] [--isjson ISJSON] [--output OUTPUT] [--nostdout nostdout] UUID DATA

Create a uBirch Protocol Package (UPP)

positional arguments:
  UUID                  UUID to work with; e.g.: 56bd9b85-6c6e-4a24-bf71-f2ac2de10183
  DATA                  data to be packed into the UPP or hashed; e.g.: {"t": 23.4, "ts": 1624624140}

optional arguments:
  -h, --help            show this help message and exit
  --version VERISON, -v VERISON
                        version of the UPP; 0x21 (unsigned; NOT IMPLEMENTED), 0x22 (signed) or 0x23 (chained) (default: 0x23)
  --type TYPE, -t TYPE  type of the UPP (0 < type < 256); e.g.: 0x00 (unknown), 0x32 (msgpack), 0x53 (generic), ... (default and recommended: 0x00)
  --ks KS, -k KS        keystore file path; e.g.: test.jks (default: devices.jks)
  --kspwd KSPWD, -p KSPWD
                        keystore password; e.g.: secret (default: keystore)
  --keyreg KEYREG, -r KEYREG
                        generate a key registration UPP (data and --hash will be ignored); e.g.: true, false (default: False)
  --hash HASH           hash algorithm for hashing the data; sha256, sha512 or off (disable hashing), ... (default and recommended: sha512)
  --isjson ISJSON, -j ISJSON
                        tells the script to treat the input data as json and serealize it (see EXAMPLES.md for more information); true or false (default: False)
  --output OUTPUT, -o OUTPUT
                        file to write the generated UPP to (aside from standard output); e.g. upp.bin (default: upp.bin)
  --nostdout nostdout, -n nostdout
                        do not output anything to stdout; can be combined with --output /dev/stdout; e.g.: true, false (default: False)

Note that when using chained UPPs (--version 0x23), this tool will try to load/save signatures to UUID.sig, where UUID will be replaced with the actual UUID. Make sure that the UUID.sig file is in your current working directory if you try to continue a UPP chain
using this tool.Also beware that you will only be able to access the contents of a keystore when you use the same password you used when creating it. Otherwise all contents are lost. When --hash off is set, contents of the DATA argument will be copied into the
payload field of the UPP. Normally used for special messages (e.g. key registration). For more information on possible values for --type and --version see https://github.com/ubirch/ubirch-protocol.
```
The script allows multiple modes of operation which can be set through different command line arguments. Some of those directly set fields in the resulting UPP. Please consult the [uBirch Protocol Readme](https://github.com/ubirch/ubirch-protocol#basic-message-format) for further information on those fields and their possible values.
- `--version/-v` This flag sets the version field of the UPP. The version field actually consists of two sub-fields. The higher four bits set the actual version (`1` or `2`) and the "mode". The higher four bits will be set to two (`0010`) set in almost all usecases. The mode can eather be a simple UPP without a signature, an UPP with a signature and an UPP with a signature + the signature of the previous UPP embedded into it. The one would be called a _Chained UPP_. Unsigned UPPs (`-v 0x21`) are not implemented. Signed UPPs have `-v 0x22` and chained ones `-v 0x23`.
- `--type/-t` This flag sets the type field of the UPP. It it used to indicate what the UPP contains/should be used for. It can be set to `0x00` in most cases. One of the cases in which a specific value is required are Key Registration Messages, as described in [Registering a Public Key](#registering-a-public-key).
- `--k/-k` The path to the keystore that contains the keypair for the device or should be used to store a newly generated keypair. If the keystore pointed to by this parameter doesn't exist, the script will simple create it.
- `--kspwd/-p` The password to decrypt/encrypt the keystore. You must remember this or you will lose access to the keystore and all its contents.
- `--keyreg/-k` Tells the script that the UPP that should be generated is a key registration UPP. The effect of that is that the script will ignore any custom input data and the `--hash` parameter (below). Instead, the UPP will contain the public key certificate. This parameter is a binary flag which can have two values: `true` or `false`.
- `--hash` Sets the hash algorithm to used to hash the input data. The produced hash will then be inserted into the payload field of the UPP. This parameter can have three values: `sha512`, `sha256` and `off`. When set to off, the input data will be directly put into the UPP without hashing it. This is only useful in some special cases like when manually assembling key registration messages (normally the `--keyreg` option should be used for that).
- `--isjson/-j` A binary flag that indicates that the input data is in JSON format. The script will serialize the JSON object before calculating the hash. This has the advantage one doesn't have to remember the order in which fields are listed in a JSON object to still be able to reconstruct the hash later on. Serializing the JSON is done like this: `json.dumps(self.data, separators=(',', ':'), sort_keys=True, ensure_ascii=False)` where `self.data` contains the JSON object which was loaded like this: `self.data = json.loads(self.dataStr)` where `dataStr` contains the input string which should represent a JSON object. This flag can have two values: `true` or `false`.
- `--output/-o` Tells the script where to write the generated UPP to.
- `--nostdout/-n` Binary flag to disable printing of any log messages to standard output. This can be used for piping a created UPP to another program. For this `--output /dev/stdout` would have to be set.
- `UUID` The UUID of the device as a hex-string, like `f5ded8a3-d462-41c4-a8dc-af3fd072a217`.
- `DATA` The data that is going to be hashed. If `--isjson true` is provided, it has to be a string representing a valid JSON object. **Note** that even though this argument will be ignored when `--keyreg true` is set, it must still exist.

One common examples of using this script might look like this:
```
$ python3 upp-creator.py --version 0x23 --isjson true --output upp.bin --hash sha256 f5ded8a3-d462-41c4-a8dc-af3fd072a217 '{
    "ts": 1625163338,
    "T": 11.2,
    "H": 35.8,
    "S": "OK"
}'
2021-07-02 15:07:53,040                 root        init_keystore() INFO     Public/Verifying key for "f5ded8a3-d462-41c4-a8dc-af3fd072a217" [base64]: "dsbKkw9HpsTvlLGgmiaYAM4M/ytFcySoF5UbfScffxg="
2021-07-02 15:07:53,041                 root      prepare_payload() INFO     Serialized data JSON: "{"H":35.8,"S":"OK","T":11.2,"ts":1625163338}"
2021-07-02 15:07:53,041                 root      prepare_payload() INFO     UPP payload (sha256 hash of the data) [base64]: "dfQu7wBCL2aCuAqWLkyHEXCzTlKHdfMr7PMrxEcwY6A="
2021-07-02 15:07:53,041                 root           create_upp() INFO     Generating a chained signed UPP for UUID "f5ded8a3-d462-41c4-a8dc-af3fd072a217"
2021-07-02 15:07:53,041                 root       show_store_upp() INFO     UPP [hex]: "9623c410f5ded8a3d46241c4a8dcaf3fd072a217c440cbe84f33c1d80a9a2a68f10c61c843567035d19179a703bb5e0aff4e920d9b8535acb171f1fd55271371d199fc985f33cf0b31f3c6ecfa7be684b561ac6d900f00c42075f42eef00422f6682b80a962e4c871170b34e528775f32becf32bc4473063a0c440ccc7e39d9a1acbf39d307d08d5b5f74218016e0b9e74d1efc7640c540c4cda1bf182b389a7ed9fd3fefb047ce6cf513dd1a047193ed0a13110f727fef4421102"
2021-07-02 15:07:53,041                 root       show_store_upp() INFO     UPP written to "upp.bin"
```
Keep in mind that when using chained UPPs (`--version 0x23`) you should anchor each UPP, or the signature chain will be broken. This won't cause any errors, but defeat the purpose of chaining UPPs.

### Sending a UPP
After creating the UPP, it can be sent to the uBirch backend where it will be verified (the backend will use the registered public/verifying key to check the signature) and anchored into the blockchain. The `upp-sender.py` script can be used for that.
```
$ python3 upp-sender.py --help
usage: upp-sender.py [-h] [--env ENV] [--input INPUT] [--output OUTPUT] UUID AUTH

Send a uBirch Protocol Package (UPP) to uBirch Niomon

positional arguments:
  UUID                  UUID to work with; e.g.: 56bd9b85-6c6e-4a24-bf71-f2ac2de10183
  AUTH                  uBirch device authentication token

optional arguments:
  -h, --help            show this help message and exit
  --env ENV, -e ENV     environment to operate in; dev, demo or prod (default: dev)
  --input INPUT, -i INPUT
                        UPP input file path; e.g. upp.bin or /dev/stdin (default: upp.bin)
  --output OUTPUT, -o OUTPUT
                        response UPP output file path (ignored for key registration UPPs); e.g. response_upp.bin (default: response_upp.bin)
```
For this script there aren't that many parameters, since the task is rather easy and straight forward.
- `--env/-e` The env to operate on. This parameter decides wether the UPP will be sent to `niomon.prod.ubirch.com`, `niomon.demo.ubirch.com` or `niomon.dev.ubirch.com`. The value can either be `prod`, `demo` or `dev`. It must match the stage the UUID is registered on.
- `--input/-i` Specifies where to read the UPP to be sent from. This can be a normal file path or also `/dev/stdin` if, for example, the UPP will be piped to this script from another script (like `upp-creator.py`). In most cases the UPP will just be read from some file.
- `--output/-o` Normally the uBirch backend will respond to the UPP with another UPP. This parameter sets the location to write that response-UPP to.
- `UUID` The UUID of the device that generated the UPP as a hex-string.
- `AUTH` The auth token for the device on the specified stage as a hex-string.
Continuing from the example above (see [Creating a UPP](#creating-a-upp)), the send-command might look like this:
```
$ python upp-sender.py --env demo --input upp.bin --output response_upp.bin f5ded8a3-d462-41c4-a8dc-af3fd072a217 xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
2021-07-02 15:21:36,966                 root             read_upp() INFO     Reading the input UPP for "f5ded8a3-d462-41c4-a8dc-af3fd072a217" from "upp.bin"
2021-07-02 15:21:37,722                 root             send_upp() INFO     The UPP for "f5ded8a3-d462-41c4-a8dc-af3fd072a217" was accepted
2021-07-02 15:21:37,723                 root             send_upp() INFO     9623c4109d3c78ff22f34441a5d185c636d486ffc440ccc7e39d9a1acbf39d307d08d5b5f74218016e0b9e74d1efc7640c540c4cda1bf182b389a7ed9fd3fefb047ce6cf513dd1a047193ed0a13110f727fef442110200c42049950c5d778045a7b20c5e4db820c38100000000000000000000000000000000c440577f3679edbf96120066b9d1a794651817ec36fe6d1728841a7110ef0a2692c1e72827e8a48f98eefb42777b4fafd47c6bd7931e21c3c983c6f0c8a99144f90c
2021-07-02 15:21:37,723                 root   store_response_upp() INFO     The response UPP has been written to "response_upp.bin"
```

### Verifying a UPP
To make sure that the response UPP actually was sent by the uBirch backend, its signature can be checked. The example script for that is `upp-verifier.py`. It knows the UUID and verifying/public key for each uBirch Niomon stage end checks if the signature of the response UPP is valid.

```
$ python3 upp-verifier.py --help
usage: upp-verifier.py [-h] [--verifying-key VK] [--verifying-key-uuid UUID] [--input INPUT]

Check if a UPP is valid/properly signed

optional arguments:
  -h, --help            show this help message and exit
  --verifying-key VK, -k VK
                        key to be used for verification; any verifying key in hex like "b12a906051f102881bbb487ee8264aa05d8d0fcc51218f2a47f562ceb9b0d068"
  --verifying-key-uuid UUID, -u UUID
                        the UUID for the key supplied via -k (only needed when -k is specified); e.g.: 6eac4d0b-16e6-4508-8c46-22e7451ea5a1
  --input INPUT, -i INPUT
                        UPP input file path; e.g. upp.bin or /dev/stdin (default: upp.bin)

Note that when trying to verify a UPP sent by the uBirch backend (Niomon) a verifying key doesn't have to be provided via the -k option. Instead, this script will try to pick the correct stage key based on the UUID which is contained in the UPP, identifying the creator. If the UUID doesn't match any Niomon stage and no key was specified using -k, an error message will be printed.
```
- `--verifying-key/-k` If not trying to verify a UPP coming from uBirch Niomon but from another source, the verifying key for that source needs to be provided. This parameter expects the key as a hex-string like `b12a906051f102881bbb487ee8264aa05d8d0fcc51218f2a47f562ceb9b0d068`.
- `--verifying-key-uuid/-u` The UUID for the verifying key from `--verifying-key`. This parameter will be ignored when `--verifying-key` is not set. Not setting this parameter when `--verifying-key` is set will cause an error.
- The file path to read the UPP from.

```
$ python3 upp-verifier.py --input response_upp.bin
2021-07-02 15:43:36,273                 root             read_upp() INFO     Reading the input UPP from "response_upp.bin"
2021-07-02 15:43:36,274     ubirch.ubirch_ks           _load_keys() WARNING  creating new key store: -- temporary --
2021-07-02 15:43:36,274                 root         get_upp_uuid() INFO     UUID of the UPP creator: "07104235-1892-4020-9042-00003c94b60b"
2021-07-02 15:43:36,275                 root           verify_upp() INFO     Signature verified - the UPP is valid!
```

### Examining a UPP
To examine the contents (Version Field, Type Field, UUID, Signature, Payload, Previous Signature) of an UPP, the `upp-unpacker.py` script can be used like this:
```
$ python3 upp-unpacker.py response_upp.bin
-    Version: 0x23
-       UUID: 9d3c78ff-22f3-4441-a5d1-85c636d486ff
- prev.Sign.: zMfjnZoay/OdMH0I1bX3QhgBbguedNHvx2QMVAxM2hvxgrOJp+2f0/77BHzmz1E90aBHGT7QoTEQ9yf+9EIRAg==
       [hex]: ccc7e39d9a1acbf39d307d08d5b5f74218016e0b9e74d1efc7640c540c4cda1bf182b389a7ed9fd3fefb047ce6cf513dd1a047193ed0a13110f727fef4421102 (64 bytes)
-       Type: 0x00
-    Payload: SZUMXXeARaeyDF5NuCDDgQAAAAAAAAAAAAAAAAAAAAA=
       [hex]: 49950c5d778045a7b20c5e4db820c38100000000000000000000000000000000 (32 bytes)
-  Signature: V382ee2/lhIAZrnRp5RlGBfsNv5tFyiEGnEQ7womksHnKCfopI+Y7vtCd3tPr9R8a9eTHiHDyYPG8MipkUT5DA==
       [hex]: 577f3679edbf96120066b9d1a794651817ec36fe6d1728841a7110ef0a2692c1e72827e8a48f98eefb42777b4fafd47c6bd7931e21c3c983c6f0c8a99144f90c (64 bytes)
```
_The UUID in this response UPP doesn't match the one from examples above because the UPP was sent from Niomon-Dev._

### Checking the anchoring status of an UPP
uBirch Niomon accepting the UPP doesn't mean that it is anchored yet. This process takes place in certain intervals, so one might have to wait a short while. The script for that task is `upp-anchoring-status.py`.
```
$ python3 upp-anchoring-status.py -h
usage: upp-anchoring-status.py [-h] [--ishash ISHASH] [--env ENV] INPUT

Requests the verification/anchoring of a UPP from the uBirch backend

positional arguments:
  INPUT                 input hash or upp path (depends on --ishash)

optional arguments:
  -h, --help            show this help message and exit
  --ishash ISHASH, -i ISHASH
                        sets if INPUT is being treated as a hash or upp path; true or false (default: False)
  --env ENV, -e ENV     the environment to operate in; dev, demo or prod (default: dev)

When --ishash/-i is set to true, the input argument is treated as a base64 payload hash. Otherwise, it is expected to be some kind of path to read a UPP from. This can be a file path or also /dev/stdin if the UPP is piped to this program via standard input.
```
- `--ishash/-i` A boolean specifying wether the input data is a payload hash or an UPP. The payload hash is what is actually used to look up anchoring information about the UPP. This script can either extract it from a given UPP or just use the hash directly if provided. If directly provided, it must be base64 encoded (see the last example of this sub-section). `true` or `false`.
- `--env/-e` The stage to check on. Should be the one the UPP was sent to. `prod`, `demo` or `dev`.
- `INPUT` The input UPP file path or payload hash, depending on `--ishash`.

One example might be:
```
python3 upp-anchoring-status.py --env demo upp.bin
2021-07-02 16:01:46,761                 root             read_upp() INFO     Reading the input UPP from "upp.bin"
2021-07-02 16:01:46,761                 root    get_hash_from_upp() INFO     Extracted UPP hash: "ToBgV89kXaWU0YHblha7qUXn0gohzpKoIS515cmSl4Y="
2021-07-02 16:01:46,761                 root           get_status() INFO     Requesting anchoring information from: "https://verify.demo.ubirch.com/api/upp/verify/anchor"
2021-07-02 16:01:46,950                 root           get_status() INFO     The UPP is known to the uBirch backend! (code: 200)
Curr. UPP: "liPEEPXe2KPUYkHEqNyvP9ByohfEQMzH452aGsvznTB9CNW190IYAW4LnnTR78dkDFQMTNob8YKziaftn9P++wR85s9RPdGgRxk+0KExEPcn/vRCEQIAxCBOgGBXz2RdpZTRgduWFrupRefSCiHOkqghLnXlyZKXhsRAZw4gMp5Wlq5Sij9UQrjMfhxdmeoY6IsVS7Aq8MLZyUT5CvTeEK/4kt4N55tE8pYVN7G+FxEYwvYfwDLZPqViBw=="
Prev. UPP: "liPEEPXe2KPUYkHEqNyvP9ByohfEQMvoTzPB2AqaKmjxDGHIQ1ZwNdGReacDu14K/06SDZuFNayxcfH9VScTcdGZ/JhfM88LMfPG7Pp75oS1YaxtkA8AxCB19C7vAEIvZoK4CpYuTIcRcLNOUod18yvs8yvERzBjoMRAzMfjnZoay/OdMH0I1bX3QhgBbguedNHvx2QMVAxM2hvxgrOJp+2f0/77BHzmz1E90aBHGT7QoTEQ9yf+9EIRAg=="
2021-07-02 16:01:46,950                 root           get_status() INFO     The UPP has NOT been anchored into any blockchains yet! Please retry later
```
Here it is visible that the backend knows the UPP and that it is valid, but it hasn't been anchored yet. Additionally the output shows that The backend knows the previous UPP, indicating that the UPP is a chained UPP and not the first UPP in the chain. When using unchained UPPs the line will change to: `Prev. UPP: "None"`. After waiting some time and running the script again with the same parameters:
```
$ python3 upp-anchoring-status.py --env demo upp.bin
2021-07-02 16:09:34,521                 root             read_upp() INFO     Reading the input UPP from "upp.bin"
2021-07-02 16:09:34,521                 root    get_hash_from_upp() INFO     Extracted UPP hash: "ToBgV89kXaWU0YHblha7qUXn0gohzpKoIS515cmSl4Y="
2021-07-02 16:09:34,521                 root           get_status() INFO     Requesting anchoring information from: "https://verify.demo.ubirch.com/api/upp/verify/anchor"
2021-07-02 16:09:34,727                 root           get_status() INFO     The UPP is known to the uBirch backend! (code: 200)
Curr. UPP: "liPEEPXe2KPUYkHEqNyvP9ByohfEQMzH452aGsvznTB9CNW190IYAW4LnnTR78dkDFQMTNob8YKziaftn9P++wR85s9RPdGgRxk+0KExEPcn/vRCEQIAxCBOgGBXz2RdpZTRgduWFrupRefSCiHOkqghLnXlyZKXhsRAZw4gMp5Wlq5Sij9UQrjMfhxdmeoY6IsVS7Aq8MLZyUT5CvTeEK/4kt4N55tE8pYVN7G+FxEYwvYfwDLZPqViBw=="
Prev. UPP: "liPEEPXe2KPUYkHEqNyvP9ByohfEQMvoTzPB2AqaKmjxDGHIQ1ZwNdGReacDu14K/06SDZuFNayxcfH9VScTcdGZ/JhfM88LMfPG7Pp75oS1YaxtkA8AxCB19C7vAEIvZoK4CpYuTIcRcLNOUod18yvs8yvERzBjoMRAzMfjnZoay/OdMH0I1bX3QhgBbguedNHvx2QMVAxM2hvxgrOJp+2f0/77BHzmz1E90aBHGT7QoTEQ9yf+9EIRAg=="
2021-07-02 16:09:34,727                 root           get_status() INFO     The UPP has been fully anchored!
[{'label': 'PUBLIC_CHAIN', 'properties': {'timestamp': '2021-07-02T14:03:22.093Z', 'hash': '0xd1fe1f27a315089e5522eb7c8124962774b335c24d1ed7281091b447a8d3bca2', 'public_chain': 'ETHEREUM_TESTNET_RINKEBY_TESTNET_NETWORK', 'prev_hash': '06700cdb7b196292eceac71520fad2e46890e2d8f74510f1bc4296c6a0e16a631cff533989c9b83363f72051105b8f0bfaf59706a5258d8d275abc93d67d5b4d'}}]
```
The UPP has been anchored. **Note** that when running on `prod` the output regarding the anchoring status will be significantly longer:
```
$ python3 upp-anchoring-status.py --env prod --ishash true "dfQu7wBCL2aCuAqWLkyHEXCzTlKHdfMr7PMrxEcwY6A="
2021-07-02 16:13:47,509                 root  get_hash_from_input() INFO     Extracted hash from input: "dfQu7wBCL2aCuAqWLkyHEXCzTlKHdfMr7PMrxEcwY6A="
2021-07-02 16:13:47,509                 root           get_status() INFO     Requesting anchoring information from: "https://verify.prod.ubirch.com/api/upp/verify/anchor"
2021-07-02 16:13:47,631                 root           get_status() INFO     The UPP is known to the uBirch backend! (code: 200)
Curr. UPP: "liPEEAi4JX1SUEaGhzAnqUf6pn3EQA1F2OFz+pQfCw7yxznodtsSf5ubCXPjHOFNWPexyiNFVHouv4m2mcDHzu8icxoD1U8pXFtXscsFrYy3+oCfPgoAxCB19C7vAEIvZoK4CpYuTIcRcLNOUod18yvs8yvERzBjoMRADipQZBD9bOdYezTD49h8MuAGBspO+PCkHFAMor8H3OZGRKXs0i4Fa4ICG0VV8B6PtVzoKz5vf8m6pWGFAb/wBQ=="
Prev. UPP: "liPEEAi4JX1SUEaGhzAnqUf6pn3EQOeEqF4lo+xT9RF2ygDx9+anv14fykUolJ9gmKuTTjmzc05qXnjhs+sdQtwN7To21DBrCeDDmK4MYFixx/umBAoAxEAns4128paQWJKi9D+W9UzQqpWtOtg1474cDWvxHTMSGnP87f6IllmqA+DHJ3Xe6LZ47hlbjUsLJtAiYtS1u1hBxEANRdjhc/qUHwsO8sc56HbbEn+bmwlz4xzhTVj3scojRVR6Lr+JtpnAx87vInMaA9VPKVxbV7HLBa2Mt/qAnz4K"
2021-07-02 16:13:47,631                 root           get_status() INFO     The UPP has been fully anchored!
[{'label': 'PUBLIC_CHAIN', 'properties': {'timestamp': '2021-07-02T13:46:45.949Z', 'hash': '0xc32ccbe70ed727a1842f998d56d9928a9a30e201aef91bb08d9ac7faf931dac6', 'public_chain': 'ETHEREUM-CLASSIC_MAINNET_ETHERERUM_CLASSIC_MAINNET_NETWORK', 'prev_hash': '4d79e0d331b1fe057b3c9ee7cb595c371ec0ea764147029a862b3cffce808ae049ec40a6e5cddbd6ee90e4d36955cd2e08ab1f4ef1ccc8c013710617bd689cfe'}}, {'label': 'PUBLIC_CHAIN', 'properties': {'timestamp': '2021-07-02T13:58:24.677Z', 'hash': '0x65438aab8904c467ceb5b22e6b1a4198eeb056647a8b7a9ece0d03739a79a0bb', 'public_chain': 'GOV-DIGITAL_MAINNET_GOV_DIGITAL_MAINNET_NETWORK', 'prev_hash': 'e98a502253ec3aebd9af29cd368e3db899e5c04d6e8214be17856055b9301b63ce2ddb34038c4d3366ab9b4be28f755041f3a089d36c3516d84b0a95741289e3'}}]
```

### Verifying a measurement
Being able to check if a UPP is anchored and valid is nice, but in a real usecase it might not be that useful. That's because usually the goal is the check if some data is valid. Verifying a UPP doesn't really help in that case, since it is not possible to reverse the hash contained in the UPP back to the original data. That's why one shouldn't bother to store sent UPPs, but rather the measurements these UPPs are based on. Those can then be hashed, and the hash can be looked up. The `data-verifier.py` script does exactly that. It has similar behaviour to the `upp-anchoring-status.py` script, see [Checking the anchoring status of an UPP](#checking-the-anchoring-status-of-an-upp).
```
$ python data-verifier.py -h
usage: data-verifier.py [-h] [--ispath ISHASH] [--env ENV] [--isjson ISJSON] [--hash HASH] INPUT

Check if the hash of given input data is known to the uBirch backend (verify it)

positional arguments:
  INPUT                 input data or data file path (depends on --ispath)

optional arguments:
  -h, --help            show this help message and exit
  --ispath ISPATH, -i ISPATH
                        sets if INPUT is being treated as data or data file path; true or false (default: False)
  --env ENV, -e ENV     the environment to operate in; dev, demo or prod (default: dev)
  --isjson ISJSON, -j ISJSON
                        tells the script to treat the input data as json and serealize it (see EXAMPLES.md for more information); true or false (default: True)
  --hash HASH, -a HASH  sets the hash algorithm to use; sha256, sha512 or OFF to treat the input data as hash (default: sha256)

When --ispath/-i is set to true, the input data is treated as a file path to read the actual input data from. When setting --hash/-a to off, the input argument is expected to be a valid base64 encoded hash.
```
- `--ispath/-i` Specifies wether the input is to be treated as a data-file path or direct input data. `true` or `false`.
- `--env-e` The stage to check on. Should be the one the UPP corresponding to the data was sent to. `prod`, `demo` or `dev`.
- `--isjson/-j` A binary flag that indicates that the input data is in JSON format. The script will serialize the JSON object before calculating the hash. This has the advantage one doesn't have to remember the order in which fields are listed in a JSON object to still be able to reconstruct the hash later on. Serializing the JSON is done like this: `json.dumps(self.data, separators=(',', ':'), sort_keys=True, ensure_ascii=False)` where `self.data` contains the JSON object which was loaded like this: `self.data = json.loads(self.dataStr)` where `dataStr` contains the input string which should represent a JSON object. This flag can have two values: `true` or `false`. It should only be set to `true` if the data represents a JSON object and if it also was serialized when creating the UPP.
- `--hash/-a` Sets the hashing algorithm to use. `sha256`, `sha512` or `off`. It should match the algorithm used when creating the corresponding UPP. Setting it to `off` means that the input data actually already is the hash of the data. In this case this script will simply look up the hash.

Example:
```
python data-verifier.py --env demo --isjson true --hash sha256 '{
    "ts": 1625163338,
    "T": 11.2,
    "H": 35.8,
    "S": "OK"
}'
2021-07-02 16:21:41,178                 root       serialize_json() INFO     Serialized JSON: "{"H":35.8,"S":"OK","T":11.2,"ts":1625163338}"
2021-07-02 16:21:41,178                 root   get_hash_from_data() INFO     Calculated hash: "dfQu7wBCL2aCuAqWLkyHEXCzTlKHdfMr7PMrxEcwY6A="
2021-07-02 16:21:41,178                 root           get_status() INFO     Requesting anchoring information from: "https://verify.demo.ubirch.com/api/upp/verify/anchor"
2021-07-02 16:21:41,599                 root           get_status() INFO     The hash is known to the uBirch backend! (code: 200)
Curr. UPP: "liPEEPXe2KPUYkHEqNyvP9ByohfEQMvoTzPB2AqaKmjxDGHIQ1ZwNdGReacDu14K/06SDZuFNayxcfH9VScTcdGZ/JhfM88LMfPG7Pp75oS1YaxtkA8AxCB19C7vAEIvZoK4CpYuTIcRcLNOUod18yvs8yvERzBjoMRAzMfjnZoay/OdMH0I1bX3QhgBbguedNHvx2QMVAxM2hvxgrOJp+2f0/77BHzmz1E90aBHGT7QoTEQ9yf+9EIRAg=="
Prev. UPP: "None"
2021-07-02 16:21:41,600                 root           get_status() INFO     The corresponding UPP has been fully anchored!
[{'label': 'PUBLIC_CHAIN', 'properties': {'timestamp': '2021-07-02T13:23:30.076Z', 'hash': '0x6e5956b4ac53bcaf58664e189673d4f8c7043488cf05009cc96868b146220604', 'public_chain': 'ETHEREUM-CLASSIC_TESTNET_ETHERERUM_CLASSIC_KOTTI_TESTNET_NETWORK', 'prev_hash': '644b41eee9043de5bda4b58bda1136fa0229712953678fe26486651338109b7a7135211f2b2cb646ab25d3b25198549e3c662c4791d60d343f08349b51ccc92b'}}]
```
Just like with `upp-anchoring-status.py`, it might take a short while after sending the corresponding UPP to the backend before it will be anchored.

## Sending data to the Simple Data Service
The `data-sender.py` example-script allows sending of data to the simple data service. This is only used for demo purposes.
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

## Example uBirch client implementation
`example-client.py` implements a full example uBirch client.
