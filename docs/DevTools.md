# Developer Tools

This file documents how to use the tools that can be found in [`tools/`](../tools).

## Setup - API Credentials
You should have the following information at hand:
- The stage you want to work on (later referred to as `env`)
- The `UUID` of your device or "fake" device in this instance
- The authentication token (`auth token`) for the named `UUID`

# Tools
- [A UPPs Lifecycle](#a-upps-lifecycle)
  - [Generating and managing a keypair](#generating-and-managing-a-keypair)
  - [Registering a public key](#registering-a-public-key)
  - [Payload](#payload)
    - [Processing JSON formated data](#processing-json-formated-data)
    - [Processing JSON with hashlink](#processing-json-with-hashlink)
  - [Creating a UPP](#creating-a-upp)
  - [Sending a UPP](#sending-a-upp)
  - [Verifying a UPP](#verifying-a-upp)
  - [Verifying a UPP chain](#verifying-a-upp-chain)
  - [Examining a UPP](#examining-a-upp)
  - [Checking the anchoring status of a UPP](#checking-the-anchoring-status-of-a-upp)
  - [Verifying data](#verifying-data)
- [Miscellaneous](#miscellaneous)
  - [Create a hash from an JSON object](#create-a-hash-from-an-json-object)
- [Managing Keys](#managing-keys)
	- [Managing the local KeyStore](#managing-the-local-keystore)
		- [Get key entries from the keystore](#get-key-entries-from-the-keystore)
		- [Put new key into the keystore](#put-new-key-into-the-keystore)
		- [Delete existing key from the keystore](#delete-existing-key-from-the-keystore)
	- [Managing keys inside the uBirch Identity Service](#managing-keys-inside-the-ubirch-identity-service)
		- [Get Device Key](#get-device-key)
		- [Get information about specific key](#get-information-about-specific-key)
		- [Register a new key or update key](#register-a-new-key-or-update-key)
		- [Delete a key](#delete-a-key)
		- [Revoke a key](#revoke-a-key)
	- [Registering Keys via x509 certificate](#registering-keys-via-x509-certificate)
- [Commandline Examples](#commandline-examples)
	- [Simple Data Service](#simple-data-service)
	- [Test the complete protocol](#test-the-complete-protocol)
	- [Test identity of the device](#test-identity-of-the-device)

# A UPP's Lifecycle
*From measurement to blockchain-anchored UPP*

The process needed to get a UPP to be anchored in the blockchain can be cut down into multiple steps. 
For each of those steps there is an example in this directory, demonstrating how to handle them.

### Generating and managing a keypair
To create, or more precisely, to _sign_ a UPP, a device will need a keypair. This keypair consist of a private key (_signing key_) and public key (_verifying key_). 

The signing key is used to sign UPPs and the verifying key can be used by the uBirch backend to check, if the signature is valid and belongs to the correct sender/signer. So, logically it doesn't matter who knows the verifying key, but the signing key must be kept secret all the time. 

In a real use case a device might store it in a TPM ([Trusted platform module](https://en.wikipedia.org/wiki/Trusted_Platform_Module)) or use other counter measures against attackers reading the key from the device. For this demo, keypairs will be stored in a [JKS Keystore](https://en.wikipedia.org/wiki/Java_KeyStore) using the [`pyjks`](https://pypi.org/project/pyjks/) library. Therefore, you will have to choose and remember a file path for that keystore and a password used to encrypt it. The process of actually generating the keypair is handled by the [upp-creator.py](../tools/upp-creator.py) script and explained [below](#registering-a-public-key).

To read generated keys from the KeyStore, see [below](#managing-the-local-keystore).

> **Warning:** Loosing access to the signing key, especially if it is already registered at the uBirch backend, 
will take away the ability to create and send any new UPPs from that device/UUID, 
since there is no way of creating a valid signature that would be accepted by the backend.
**More important, the backend stores and binds the verifying key, which belongs to the signing key, to the correspondent UUID,
which in case of loss, can not be used anymore.**

### Registering a public key
To enable the uBirch backend to verify a UPP, it needs to know the corresponding verifying key. Therefore, the device needs to send this key to the backend, before starting to send UPPs, which are supposed to be verified and anchored. Registering a verifying key is done by sending a special kind of UPP containing this key. This can be done by using two scripts:
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
The [upp-creator.py](upp-creator.py) script will check if the keystore specified with `--ks` contains an entry for the device with the given UUID. If it doesn´t, the script will generate a new keypair and store it. This can be seen when examining the two first log messages starting with `No keys found for` and `inserted new keypair for`. Otherwsise (if there already is a keypair for the device) the script will simple use the existent keypair. The generated key registration UPP has been saved to `keyreg_upp.bin`. Sending the UPP can be done like following (remember to put the correct value for the env of your choice):
```
$ python upp-sender.py --env demo --input keyreg_upp.bin --output response_upp.bin f5ded8a3-d462-41c4-a8dc-af3fd072a217 xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

2021-07-02 12:05:49,556                 root             read_upp() INFO     Reading the input UPP for "f5ded8a3-d462-41c4-a8dc-af3fd072a217" from "keyreg_upp.bin"
2021-07-02 12:05:49,556                 root      check_is_keyreg() INFO     The UPP is a key registration UPP - disabling identity registration check
2021-07-02 12:05:50,712                 root             send_upp() INFO     The key resgistration message for "f5ded8a3-d462-41c4-a8dc-af3fd072a217" was accepted
2021-07-02 12:05:50,712                 root             send_upp() INFO     b'{"pubKeyInfo":{"algorithm":"ECC_ED25519","created":"2021-06-27T13:12:46.000Z","hwDeviceId":"f5ded8a3-d462-41c4-a8dc-af3fd072a217","pubKey":"dsbKkw9HpsTvlLGgmiaYAM4M/ytFcySoF5UbfScffxg=","pubKeyId":"dsbKkw9HpsTvlLGgmiaYAM4M/ytFcySoF5UbfScffxg=","validNotAfter":"2022-06-27T13:12:46.000Z","validNotBefore":"2021-06-27T13:12:46.000Z"},"signature":"1e47255c7494fb54d5ab10897d53c1a38872e6a67af3d53e5ae49d6c190d0aaab70741a1af9b08793aaae82ea5a207402d5a15c563b859525e193a05f0a6510b"}'
```
After the command successfully completed there should be an entry in the `PublicKeys` tab of the device at [console.demo.ubirch.com](console.demo.ubirch.com). 
If you are using a different `env` then `demo`, please replace this part of the URL.

### Payload
In general the Payload of a UPP can be all kind of data. However, the Ubirch approach is based on the separation of the data itself and its fingerprint. The fingerprint can be generated with a hashing digestion of the data. The currently used hashing algorithms are `SHA256` and `SHA512`, but can also be differnt ones. By only storing the `hash` (fingerprint), ubirch does not need to know the `data`, but the owner of the `data` needs to know the process of generating the `hash`. 

The simplest way is to take the `data` as a binary blob, calculate the `hash` over it and put this into the `payload` field.

#### Processing JSON formated data
Many data processing units prefer using the [JSON](https://www.json.org/json-en.html) interchange format for their data, because it is readable by humans and has lots of flexibility. This flexibility for examples allows to change order of the elements or use different separators and whitespaces for the representation of the same data. This on the other hand leads to different binary representations of the data, thus also the hashes of the data will be different and cannot be verified. 

In order to always generate the same hash form a JSON object, the elements need to be sorted and harmonized, by removing the whitespace and using the same separators. 
An Example is shown below:
##### JSON data
```python
data = {
  "timestamp": 1625163338,
  "temperature": 11.2,
  "humidity": 35.8,
  "status": "OK"
}
```
##### Harmonized JSON data string
```python
serialized = json.dumps(data, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode()
```
This will create a string from the above examplary JSON object:
`b'{"humidity":35.8,"status":"OK","temperature":11.2,"timestamp":1656943520}'`

##### Hash of data 
```python
payload_hash = hashlib.sha256(serialized).digest()
```
To read the `payload_hash` it is hexlified:
`b'4909275b83319d91e15f52ccfb79be7303c3579eb858722710bd21f6c3b87828'`

#### Processing JSON with hashlink
TODO describe this process 


### Creating a UPP
To generate a UPP (Ubirch Protocol Package), the script [`upp-creator.py`](../tools/upp-creator.py) can be used.
The resulting UPP will not contain the actual data, but the hash of it. 
This script allows multiple modes of operation, which can be set through different command line arguments. Some of those directly set fields in the resulting UPP. Please consult the [uBirch Protocol Readme](../README.md) for further information on those fields and their possible values.

```
$ python3 tools/upp-creator.py -h
usage: upp-creator.py [-h] [--version VERSION] [--type TYPE] [--ks KS] [--kspwd KSPWD] [--keyreg KEYREG] [--hash HASH] [--isjson ISJSON] [--output OUTPUT] [--nostdout nostdout] [--ishl ISHASHLINK] [--ecdsa ECDSA] UUID DATA

Create a uBirch Protocol Package (UPP)

positional arguments:
  UUID                  UUID to work with; e.g.: 56bd9b85-6c6e-4a24-bf71-f2ac2de10183
  DATA                  data to be packed into the UPP or hashed; e.g.: {"t": 23.4, "ts": 1624624140}

optional arguments:
  -h, --help            show this help message and exit
  --version VERSION, -v VERSION
                        version of the UPP; 0x21 (unsigned; NOT IMPLEMENTED), 0x22 (signed) or 0x23 (chained) (default: 0x23)
  --type TYPE, -t TYPE  type of the UPP (0 < type < 256); e.g.: 0x00 (unknown), 0x32 (msgpack), 0x53 (generic), ... (default and recommended: 0x00)
  --ks KS, -k KS        keystore file path; e.g.: test.jks (default: devices.jks)
  --kspwd KSPWD, -p KSPWD
                        keystore password; e.g.: secret (default: keystore)
  --keyreg KEYREG, -r KEYREG
                        generate a key registration UPP (data and --hash will be ignored); e.g.: true, false (default: False)
  --hash HASH           hash algorithm for hashing the data; sha256, sha512 or off (disable hashing), ... (default and recommended: sha512)
  --isjson ISJSON, -j ISJSON
                        tells the script to treat the input data as json and serialize it (see docs/DevTools.md for more information); true or false (default: False)
  --output OUTPUT, -o OUTPUT
                        file to write the generated UPP to (aside from standard output); e.g. upp.bin (default: upp.bin)
  --nostdout nostdout, -n nostdout
                        do not output anything to stdout; can be combined with --output /dev/stdout; e.g.: true, false (default: False)
  --ishl ISHASHLINK, -l ISHASHLINK
                        implied --isjson to be true; if set to true, the script will look for a hashlink list in the json object and use it to decide which fields to hash; true or false (default: False)
  --ecdsa ECDSA, -c ECDSA
                        if set to true, the script will generate a ECDSA key (NIST256p, SHA256) instead of an ED25519 key in case no key was found for the UUID in the given keystore (default: False)

Note that when using chained UPPs (--version 0x23), this tool will try to load/save signatures to UUID.sig, where UUID will be replaced with the actual UUID. Make sure that the UUID.sig file is in your current working directory if you try to continue a UPP chain using this tool.Also beware that you will only be able to access the
contents of a keystore when you use the same password you used when creating it. Otherwise all contents are lost. When --hash off is set, contents of the DATA argument will be copied into the payload field of the UPP. Normally used for special messages (e.g. key registration). For more information on possible values for --type and
--version see https://github.com/ubirch/ubirch-protocol.
```

An example of using this script is:
```
$ python3 tools/upp-creator.py --version 0x23 --isjson true --output upp.bin --hash sha256 f5ded8a3-d462-41c4-a8dc-af3fd072a217 '{
  "timestamp": 1625163338,
  "temperature": 11.2,
  "humidity": 35.8,
  "status": "OK"
}'
2023-07-27 17:45:10,167                 root        init_keystore() INFO     Public/Verifying key for "f5ded8a3-d462-41c4-a8dc-af3fd072a217" [ED25519, base64]: "UglvUsgYwp4iM+IqM7titpIPwjThhufokGzTVSObOZU="
2023-07-27 17:45:10,167                 root      prepare_payload() INFO     Serialized data JSON: "{"humidity":35.8,"status":"OK","temperature":11.2,"timestamp":1625163338}"
2023-07-27 17:45:10,167                 root      prepare_payload() INFO     UPP payload (sha256 hash of the data) [base64]: "SQknW4MxnZHhX1LM+3m+cwPDV564WHInEL0h9sO4eCg="
2023-07-27 17:45:10,167                 root           create_upp() INFO     Generating a chained signed UPP for UUID "f5ded8a3-d462-41c4-a8dc-af3fd072a217"
2023-07-27 17:45:10,169                 root       show_store_upp() INFO     UPP [hex]: "9623c410f5ded8a3d46241c4a8dcaf3fd072a217c440fdc2d28afeb3e3c0f4c8db4028a496c642874cf4acc1fa2454e2bd5fc6d3312df83213e061c0290f7f3d5deb5529915d5cb2c7e6fab6d9946553e13cc76fa40f00c4204909275b83319d91e15f52ccfb79be7303c3579eb858722710bd21f6c3b87828c440b15e3dd5b9a435a72c6779d0358ea8dc659af75d721a918126156798ea33c00950c1c69f6f874d37729324dae76294a66ff84d9ffd64e01532b5e8b7bf84c709"
2023-07-27 17:45:10,170                 root       show_store_upp() INFO     UPP written to "upp.bin"
```
Keep in mind that if you use chained UPPs (`--version 0x23`) you should anchor each UPP, or the signature chain will be broken. This won't cause any errors, but the advantage of chaining UPPs and thereby knowing the correct order of them, will get lost.

### Sending a UPP
After creating the UPP, it can be sent to the uBirch backend where it will be verified and anchored in the blockchain. The ubirch backend will use the registered public/verifying key to check the signature. The [`upp-sender.py`](../tools/upp-sender.py) script can be used for that.
```
$ python3 tools/upp-sender.py -h
usage: upp-sender.py [-h] [--ishex ISHEX] [--env ENV] [--input INPUT] [--output OUTPUT] UUID AUTH

Send a uBirch Protocol Package (UPP) to uBirch Niomon

positional arguments:
  UUID                  UUID to work with; e.g.: 56bd9b85-6c6e-4a24-bf71-f2ac2de10183
  AUTH                  uBirch device authentication token

optional arguments:
  -h, --help            show this help message and exit
  --ishex ISHEX, -x ISHEX
                        if true, the input will be interpreted as a hex-encoded string (default: False)
  --env ENV, -e ENV     environment to operate in; dev, demo or prod (default: demo)
  --input INPUT, -i INPUT
                        UPP input file path; e.g. upp.bin or /dev/stdin (default: upp.bin)
  --output OUTPUT, -o OUTPUT
                        response UPP output file path (ignored for key registration UPPs); e.g. response_upp.bin (default: response_upp.bin)
```

An Example of using this script is:
```
$ python3 tools/upp-sender.py --env demo --input upp.bin --output response_upp.bin f5ded8a3-d462-41c4-a8dc-af3fd072a217 xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
2023-07-27 17:59:53,233                 root             read_upp() INFO     Reading the input UPP for "f5ded8a3-d462-41c4-a8dc-af3fd072a217" from "upp.bin"
2023-07-27 17:59:53,233                 root             init_api() INFO     Configuring the API to use the 'demo' environment!
2023-07-27 17:59:53,722                 root             send_upp() INFO     The UPP for "f5ded8a3-d462-41c4-a8dc-af3fd072a217" was accepted
2023-07-27 17:59:53,723                 root             send_upp() INFO     9623c4109d3c78ff22f34441a5d185c636d486ffc440ccc7e39d9a1acbf39d307d08d5b5f74218016e0b9e74d1efc7640c540c4cda1bf182b389a7ed9fd3fefb047ce6cf513dd1a047193ed0a13110f727fef442110200c42049950c5d778045a7b20c5e4db820c38100000000000000000000000000000000c440577f3679edbf96120066b9d1a794651817ec36fe6d1728841a7110ef0a2692c1e72827e8a48f98eefb42777b4fafd47c6bd7931e21c3c983c6f0c8a99144f90c
2023-07-27 17:59:53,723                 root   store_response_upp() INFO     The response UPP has been written to "response_upp.bin"
```

### Verifying a UPP
UPPs can be verified locally, if the public key of the UPP creator is known. 
To verify a UPP, the [`upp-verifier.py`](../tools/upp-verifier.py) script can be used. 

The usage and the parameter set are shown below:
```
$ python3 tools/upp-verifier.py -h
usage: upp-verifier.py [-h] [--verifying-key VK] [--verifying-key-uuid UUID] [--ishex ISHEX] [--isecd ISECD] [--input INPUT]

Check if a UPP is valid/properly signed

optional arguments:
  -h, --help            show this help message and exit
  --verifying-key VK, -k VK
                        key to be used for verification; any verifying key in hex like "b12a906051f102881bbb487ee8264aa05d8d0fcc51218f2a47f562ceb9b0d068"
  --verifying-key-uuid UUID, -u UUID
                        the UUID for the key supplied via -k (only needed when -k is specified); e.g.: 6eac4d0b-16e6-4508-8c46-22e7451ea5a1
  --ishex ISHEX, -x ISHEX
                        Sets whether the UPP input data is a hex string or binary; e.g. true, false (default: false)
  --isecd ISECD, -c ISECD
                        Sets whether the key provided with -k is a ECDSA NIST256p SHA256 key (true) or a ED25519 key (false) (default: false)
  --input INPUT, -i INPUT
                        UPP input file path; e.g. upp.bin or /dev/stdin (default: /dev/stdin)

Note that when trying to verify a UPP sent by the uBirch backend (Niomon) a verifying key doesn't have to be provided via the -k option. Instead, this script will try to pick the correct stage key based on the UUID which is contained in the UPP, identifying the creator.If the UUID doesn't match any Niomon stage and no key was specified using -k, an error message will be printed.
```
An Example of using this script to verify the backend response is:
```
$ python3 tools/upp-verifier.py --input response_upp.bin
2021-07-02 15:43:36,273                 root             read_upp() INFO     Reading the input UPP from "response_upp.bin"
2021-07-02 15:43:36,274     ubirch.ubirch_ks           _load_keys() WARNING  creating new key store: -- temporary --
2021-07-02 15:43:36,274                 root         get_upp_uuid() INFO     UUID of the UPP creator: "07104235-1892-4020-9042-00003c94b60b"
2021-07-02 15:43:36,275                 root           verify_upp() INFO     Signature verified - the UPP is valid!
```

An Example of using this script to verify an abritrary UPP with correspondent UUID and public key is:
```
$ python3 tools/upp-verifier.py -k fb5be8d6e2c65165dd4b77def906700a4da4dfd67c488577c783ca0bdef5d346123f4f22f506ba232ddffb04ee29d2033647d6588b8782efb6da91bd607e32ed -u 98880181-4770-44da-85a9-da86a6ccaa1f -x true -c true
2023-07-27 15:53:06,169                 root             read_upp() INFO     Reading the input UPP from "/dev/stdin"
9623c41098880181477044da85a9da86a6ccaa1fc44075812bd144fff4a6ba9e5dc018aa1e92fd72ab7e41037eded5dc9421512b2532b4885c67a293a208febaf71e10c37086fc0616031ec293a44dd11ca1f1809e8f00c440da3ac02acb9140ec6c94f42ca41c3e9f58df3a0d666478f2e21b457dbe0f992315c9a8a24cec9bf92a2748132340835fffc2741bdce21739952db502bb123c43c440f8141fb052fd682d660399412eadb10e17591632ac2541dcbdfcedc048cdfe0dfa85962526c398bf452c8d6386998749ecb72cd8e886459d24efcb5f88dca83f
2023-07-27 15:53:15,146     ubirch.ubirch_ks           _load_keys() WARNING  creating new key store: -- temporary --
2023-07-27 15:53:15,146                 root         check_cli_vk() INFO     Loading the key as ECDSA NIST256p SHA256 verifying key
2023-07-27 15:53:15,146                 root         check_cli_vk() INFO     Inserted "98880181-4770-44da-85a9-da86a6ccaa1f": "fb5be8d6e2c65165dd4b77def906700a4da4dfd67c488577c783ca0bdef5d346123f4f22f506ba232ddffb04ee29d2033647d6588b8782efb6da91bd607e32ed" (UUID/VK) into the keystore
2023-07-27 15:53:15,146                 root         get_upp_uuid() INFO     UUID of the UPP creator: "98880181-4770-44da-85a9-da86a6ccaa1f"
2023-07-27 15:53:15,153                 root           verify_upp() INFO     Signature verified - the UPP is valid!
```

### Verifying a UPP chain
When working with `chained UPPs` it can be useful to check whether the chain is in order and valid. For
this task, the [`upp-chain-checker.py`](../tools/upp-chain-checker.py) can be used. It reads in a list of UPPs,
verifies the signature of each UPP and compares the `prevsig` field with the `signature` of the last UPP.
If at any point something doesn't match up, it will print an error message along with the number of the
UPP at which the chain is broken or something went wrong. The UPP list can either be read directly from a file
which contains them in binary or hex-encoded, separated by newlines, or from a JSON file which contains
a list of hex-encoded UPPs.

```
$ python3 tools/upp-chain-checker.py -h
usage: upp-chain-checker.py [-h] [--is-json ISJSON] [--is-hex ISHEX] INPUTFILE VK UUID

Check if a sequence of chained UPPs is valid/properly signed and correctly chained

positional arguments:
  INPUTFILE             Input file path; e.g. upp_list.bin, upp_list.json or /dev/stdin
  VK                    key to be used for verification; any verifying key in hex like "b12a906051f102881bbb487ee8264aa05d8d0fcc51218f2a47f562ceb9b0d068"
  UUID                  the UUID for the verifying key; e.g.: 6eac4d0b-16e6-4508-8c46-22e7451ea5a1

optional arguments:
  -h, --help            show this help message and exit
  --is-json ISJSON, -j ISJSON
                        If true, the script expects a JSON file for INPUTFILE (see below); e.g. true, false (default: false)
  --is-hex ISHEX, -x ISHEX
                        If true, the script expects hex-encoded UPPs from the input file; e.g. true, false (default: false)

The JSON file (when using --is-json true) es expected to contain a single field called "upps", which is a list of hex-encoded UPPs. Otherwise (--is-json false). If --is-hex is true, it expects a sequence of hex-encoded UPPs separated by newlines. The third (default) scenario is that the script expects a
sequence of binary UPPs separated by newlines. If --is-json true is set, --is-hex will be ignored.

$ python3 upp-chain-checker.py -h
usage: upp-chain-checker.py [-h] [--is-json ISJSON] [--is-hex ISHEX] INPUTFILE VK UUID
```
The `VK` and `UUID` arguments work like in the [UPP-Verifier](#verifying-a-upp), with the difference
that they aren't optional and must be provided. The `VK` argument must be hexadecimal encoded, 
thus the length of an ed25519 key has to be 64 Byte and the length of an ecdsa key has to be 128 Byte.
The difference between the algorithms is only made by the length of the provided key string.

Here is an example JSON file containing four UPPs
```json
{
  "upps": [
    "9623c410ee8c4cfe9b3a43e29e9f8875cb02cec3c44025152e18f42352a7fba90b3fa30fc245587c8af1e681a77a25107137926a9ce88287e804b7989f60d9d9ea5673bc1531437fe147281b18071ac0adbe40d27d0b00c440f30a0ee67fc6f5ae5a133a012ab3931198752ee8e13084d473c1d1bd7dd000423b5ede36e5c217a2b8fe0512c5bfb3e8959f6773b812ddf98e45895ee9a7ac06c4406502e436d33edbfa8c1f82f9644344307e79dfd46c2a766083a238bfd6edca2ec6d83b2329a5b302516839bfac36b199c7593dded5bc4f0531f233ce53f94903",
    "9623c410ee8c4cfe9b3a43e29e9f8875cb02cec3c4406502e436d33edbfa8c1f82f9644344307e79dfd46c2a766083a238bfd6edca2ec6d83b2329a5b302516839bfac36b199c7593dded5bc4f0531f233ce53f9490300c440a27146b7aa7bc0194468a1e5eee816dd07861bd4036654b74812f36e721b98615aedb84bb8700b5aede01207994c20b1bac759da95a3b41f4614c975a0668883c440596c4b7b840681ce89bb1d6dbb2ccf1108e2007a68ed39fce71783c6d1e8b39ba78769866bacbc281a64d8f7d9ff20fd5dc6a1cf998104395e2018ad49a15a08",
    "9623c410ee8c4cfe9b3a43e29e9f8875cb02cec3c440596c4b7b840681ce89bb1d6dbb2ccf1108e2007a68ed39fce71783c6d1e8b39ba78769866bacbc281a64d8f7d9ff20fd5dc6a1cf998104395e2018ad49a15a0800c44038b971a62ce01cbbf302cb635c4c6f2faa266a5d78aa1edbda28ac8945ed51ac651b3fac2aa85b1d1685cf4424b7fbb1845a09e47b9ce69b957ceff2bcddf61dc4409c2f20ece86519f541b45b4e2aea4ea51b98c3d12014e513c303c8c9b0af7c0caab39894419dac6e4bf601c27273f9bc58c22ab9e93879fc472f381da00c1d03",
    "9623c410ee8c4cfe9b3a43e29e9f8875cb02cec3c4409c2f20ece86519f541b45b4e2aea4ea51b98c3d12014e513c303c8c9b0af7c0caab39894419dac6e4bf601c27273f9bc58c22ab9e93879fc472f381da00c1d0300c440553470115df2e2bc5d1044fa3cec93f95c9e0d9df2daa394daca465d75e3dc91d34c6cfa0d7b29081f0dd58d79deae541e890d6ef04f6cf4a32031a8e855d93bc44040f79e9feb28e4086489431b5650b74849308f5a1911f3d630711e226eef03a0b48185964b753a63e44b36d5a9794f5f3df2af0e613545c063b81c7005f9d400"
  ]
}
```
If stored in `UPP_LIST.json`, it can be used like this:
```
$ python3 upp-chain-checker.py --is-json true UPP_LIST.json 286401c523ebbfb5f6a4044e62af8ef66775f9a76a2ff2af0067ecfb4563df21 ee8c4cfe-9b3a-43e2-9e9f-8875cb02cec3
2021-11-07 15:40:58,168                 root            read_upps() INFO     Reading the input UPP json from "UPP_LIST.json"
2021-11-07 15:40:58,168                 root            read_upps() INFO     Read 4 UPPs
2021-11-07 15:40:58,168     ubirch.ubirch_ks           _load_keys() WARNING  creating new key store: -- temporary --
2021-11-07 15:40:58,168                 root         check_cli_vk() INFO     Inserted "ee8c4cfe-9b3a-43e2-9e9f-8875cb02cec3": "286401c523ebbfb5f6a4044e62af8ef66775f9a76a2ff2af0067ecfb4563df21" (UUID/VK) into the keystore
2021-11-07 15:40:58,173                 root          verify_upps() INFO     All signatures verified and prevsigs compared - the UPP chain is valid!
```
Another way of using the script is this:
```
$ echo -n -e "9623c410ee8c4cfe9b3a43e29e9f8875cb02cec3c44025152e18f42352a7fba90b3fa30fc245587c8af1e681a77a25107137926a9ce88287e804b7989f60d9d9ea5673bc1531437fe147281b18071ac0adbe40d27d0b00c440f30a0ee67fc6f5ae5a133a012ab3931198752ee8e13084d473c1d1bd7dd000423b5ede36e5c217a2b8fe0512c5bfb3e8959f6773b812ddf98e45895ee9a7ac06c4406502e436d33edbfa8c1f82f9644344307e79dfd46c2a766083a238bfd6edca2ec6d83b2329a5b302516839bfac36b199c7593dded5bc4f0531f233ce53f94903\n9623c410ee8c4cfe9b3a43e29e9f8875cb02cec3c4406502e436d33edbfa8c1f82f9644344307e79dfd46c2a766083a238bfd6edca2ec6d83b2329a5b302516839bfac36b199c7593dded5bc4f0531f233ce53f9490300c440a27146b7aa7bc0194468a1e5eee816dd07861bd4036654b74812f36e721b98615aedb84bb8700b5aede01207994c20b1bac759da95a3b41f4614c975a0668883c440596c4b7b840681ce89bb1d6dbb2ccf1108e2007a68ed39fce71783c6d1e8b39ba78769866bacbc281a64d8f7d9ff20fd5dc6a1cf998104395e2018ad49a15a08\n9623c410ee8c4cfe9b3a43e29e9f8875cb02cec3c440596c4b7b840681ce89bb1d6dbb2ccf1108e2007a68ed39fce71783c6d1e8b39ba78769866bacbc281a64d8f7d9ff20fd5dc6a1cf998104395e2018ad49a15a0800c44038b971a62ce01cbbf302cb635c4c6f2faa266a5d78aa1edbda28ac8945ed51ac651b3fac2aa85b1d1685cf4424b7fbb1845a09e47b9ce69b957ceff2bcddf61dc4409c2f20ece86519f541b45b4e2aea4ea51b98c3d12014e513c303c8c9b0af7c0caab39894419dac6e4bf601c27273f9bc58c22ab9e93879fc472f381da00c1d03\n9623c410ee8c4cfe9b3a43e29e9f8875cb02cec3c4409c2f20ece86519f541b45b4e2aea4ea51b98c3d12014e513c303c8c9b0af7c0caab39894419dac6e4bf601c27273f9bc58c22ab9e93879fc472f381da00c1d0300c440553470115df2e2bc5d1044fa3cec93f95c9e0d9df2daa394daca465d75e3dc91d34c6cfa0d7b29081f0dd58d79deae541e890d6ef04f6cf4a32031a8e855d93bc44040f79e9feb28e4086489431b5650b74849308f5a1911f3d630711e226eef03a0b48185964b753a63e44b36d5a9794f5f3df2af0e613545c063b81c7005f9d400\n" | python3 upp-chain-checker.py --is-hex true /dev/stdin 286401c523ebbfb5f6a4044e62af8ef66775f9a76a2ff2af0067ecfb4563df21 ee8c4cfe-9b3a-43e2-9e9f-8875cb02cec3

2021-11-07 15:45:00,121                 root            read_upps() INFO     Reading the input UPPs from "/dev/stdin"
2021-11-07 15:45:00,121                 root            read_upps() INFO     Read 4 UPPs
2021-11-07 15:45:00,121     ubirch.ubirch_ks           _load_keys() WARNING  creating new key store: -- temporary --
2021-11-07 15:45:00,121                 root         check_cli_vk() INFO     Inserted "ee8c4cfe-9b3a-43e2-9e9f-8875cb02cec3": "286401c523ebbfb5f6a4044e62af8ef66775f9a76a2ff2af0067ecfb4563df21" (UUID/VK) into the keystore
2021-11-07 15:45:00,127                 root          verify_upps() INFO     All signatures verified and prevsigs compared - the UPP chain is valid!
```
The UPPs are piped as hex-encoded strings separated by newlines (`\n`) to the script which has the input
file path set to `/dev/stdin`.

### Examining a UPP
To examine the contents (Version Field, Type Field, UUID, Previous Signature, Payload, Signature) of a UPP, the [`upp-unpacker.py`](../tools/upp-unpacker.py) script can be used. 
```
$ python3 tools/upp-unpacker.py 
 usage:
 python3 upp-unpacker.py [ <binary-file-name> | <UPP(hex)> | <UPP(base64)> ]
```

The script takes one argument, which is the UPP itself. This can be either a file, a hexadecimal encoded UPP string, or a base64 encoded UPP string.
An exemplary usage looks like this:
```
$ python3 tools/upp-unpacker.py response_upp.bin
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

### Checking the anchoring status of a UPP
uBirch Niomon accepting the UPP doesn't mean that it is anchored yet. This process takes place in certain intervals, so one might have to wait a short while. The script to check if a UPP was already anchored is [`upp-anchoring-status.py`](../tools/upp-anchoring-status.py).
```
$ python3 tools/upp-anchoring-status.py -h
usage: upp-anchoring-status.py [-h] [--ishash ISHASH] [--env ENV] [--ishex ISHEX] INPUT

Requests the verification/anchoring of a UPP from the uBirch backend

positional arguments:
  INPUT                 input hash or upp path (depends on --ishash)

optional arguments:
  -h, --help            show this help message and exit
  --ishash ISHASH, -i ISHASH
                        sets if INPUT is being treated as a hash or upp path; true or false (default: False)
  --env ENV, -e ENV     the environment to operate in; dev, demo or prod (default: demo)
  --ishex ISHEX, -x ISHEX
                        sets if INPUT data is a hex string or not; true or false (default: false)

When --ishash/-i is set to true, the input argument is treated as a base64 payload hash. When --ishash/-i is set to true and --ishex/-x is set to true, the input argument is treated as a hex encoded payload hash. Otherwise, it is expected to be some kind of path to read a UPP from. This can be a file path
or also /dev/stdin if the UPP is piped to this program via standard input.
```
If `INPUT` is a UPP, it can either be in binary format (default: `--ishex false`), or hexadecimal encoded (`--ishex true`).  
If `INPUT` is a hash (`--ishash true`), it can either be base64 encoded (default: `--ishex false`), or hexadecimal encoded (`--ishex true`).

One example with a UPP is:
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
Here it is visible that the backend knows the UPP and that it is valid, but it hasn't been anchored yet. Additionally, the output shows that the backend knows the previous UPP, indicating that the UPP is a chained UPP and not the first UPP in the chain. When using unchained UPPs, the line will change to: `Prev. UPP: "None"`. After waiting some time and running the script again with the same parameters:
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
The UPP has been anchored. 

> **Note:** When running on `prod` the output regarding the anchoring status will be significantly more detailed:
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

### Verifying data
Ubirch does not store the data itself, however with the [`data-verifier.py`](../tools/data-verifier.py) script it is possible to verify, if the fingerprint/hash of the data has been anchored. Therefore the input will be converted into a fingerprint/hash and afterward verified against the ubirch backend, if it has been anchored, similar to [`upp-anchoring-status.py`](../tools/upp-anchoring-status.py), see also [Checking the anchoring status of a UPP](#checking-the-anchoring-status-of-a-upp).

```
$ python tools/data-verifier.py -h
usage: data-verifier.py [-h] [--ispath ISPATH] [--env ENV] [--isjson ISJSON] [--hash HASH] [--nosend NOSEND] [--ishl ISHASHLINK] INPUT

Check if the hash of given input data is known to the uBirch backend (verify it)

positional arguments:
  INPUT                 input data or data file path (depends on --ispath)

optional arguments:
  -h, --help            show this help message and exit
  --ispath ISPATH, -i ISPATH
                        sets if INPUT is being treated as data or data file path; 'true' or 'false' (default: False)
  --env ENV, -e ENV     the environment to operate in; 'dev', 'demo' or 'prod' (default: demo)
  --isjson ISJSON, -j ISJSON
                        tells the script to treat the input data as json and serialize it; 'true' or 'false' (default: False)
  --hash HASH, -a HASH  sets the hash algorithm to use; sha256, sha512 or OFF to treat the input data as hash (default: sha256)
  --nosend NOSEND, -n NOSEND
                        if set to true, the script will only generate the hash of the input data without sending it; 'true' or 'false' (default: False)
  --ishl ISHASHLINK, -l ISHASHLINK
                        implied --isjson to be true; if set to true, the script will look for a hashlink list in the json object and use it to decide which fields to hash; 'true' or 'false' (default: False)

When --ispath/-i is set to true, the input data is treated as a file path to read the actual input data from. When setting --hash/-a to off, the input argument is expected to be a valid base64 encoded hash.
```

Example usage :
```
$ python tools/data-verifier.py --env prod --isjson true --hash sha256 '{"id":"98880181-4770-44da-85a9-da86a6ccaa1f","n":2,"ts":1690989464}'
2023-08-02 17:55:20,463                 root         process_args() INFO     Using sha256 as hashing algorithm
2023-08-02 17:55:20,463                 root       serialize_json() INFO     Serialized JSON: "{"id":"98880181-4770-44da-85a9-da86a6ccaa1f","n":2,"ts":1690989464}"
2023-08-02 17:55:20,463                 root   get_hash_from_data() INFO     Calculated hash: "CiYPLhuENVPKVFBetxomIUMoGRwn03bo4bWm9qLiTPQ="
2023-08-02 17:55:20,463                 root           get_status() INFO     Requesting anchoring information from: "https://verify.prod.ubirch.com/api/upp/verify/anchor"
2023-08-02 17:55:20,595                 root           get_status() INFO     The hash is known to the uBirch backend! (code: 200)
Curr. UPP: "liPEEJiIAYFHcETahanahqbMqh/EQHJ1vXRpAxpF+XKxshxKL4apqs4i8lAXnZP+QXwXh0EFQ3Ox5ELtPISXoKR2qeP8vbXzNghE1dAwH3QYKzzgDRQAxCAKJg8uG4Q1U8pUUF63GiYhQygZHCfTdujhtab2ouJM9MRA3mQmm18E1WuuCFUubx3S3UfgwcrO/jdwg04stzVZL84z/CwvbAIkqtVJ/E9oG9GP+xSfaSPN+XLj9mboXo+khQ=="
Prev. UPP: "liPEEJiIAYFHcETahanahqbMqh/EQKCW2Dil2MlU8NZgTaZvmftop0EHPWB+1E1LlzrTDSgB6bN6Ye59Fd870KK4GIMIJrduhMzS+ppeXIwNuRoqH+gAxCDiavwldeZ8Dic7k/G8Doc+UZ2BIMXemdEG51TzXv85EcRAcnW9dGkDGkX5crGyHEovhqmqziLyUBedk/5BfBeHQQVDc7HkQu08hJegpHap4/y9tfM2CETV0DAfdBgrPOANFA=="
2023-08-02 17:55:20,596                 root           get_status() INFO     The corresponding UPP has been fully anchored!
[{'label': 'PUBLIC_CHAIN', 'properties': {'timestamp': '2023-08-02T15:19:06.161Z', 'hash': 'd992a33a4e376deae54f2a3e876e4e7ad927dfeeefaa4f549e8778bc28679c22', 'public_chain': 'IOTA_MAINNET_IOTA_MAINNET_NETWORK', 'prev_hash': '2010897adaea33e4926cb62691c98df42d565e807ddc2c82c3060cd9578e3b4ef27b51be32d9aea74c96063111f7b94d0137cda26afa1f4339ba2903e33e6d2f'}}, {'label': 'PUBLIC_CHAIN', 'properties': {'timestamp': '2023-08-02T15:21:26.284Z', 'hash': '0x4a321f6ab9c936878866a472ee3a0aa0efdb960c6451033ebb8aa095c6b73939', 'public_chain': 'ETHEREUM_MAINNET_FRONTIER_MAINNET_NETWORK', 'prev_hash': '49134ae9ccf4a38bd0972a7752405cdbdf9017c7a1863fda6e4b8eeace871b8bfcb74d4807aeab6161b53cf0f73621a3bcce0e34d46fcd5ffe51bc2258b1b5be'}}]
```

Example for File-Input data:
```txt
python data-verifier.py --ispath true -j true data_to_verify.json -e prod
2021-07-06 12:17:31,261                 root            read_data() INFO     Reading the input data from "data_to_verify.json"
2021-07-06 12:17:31,262                 root       serialize_json() INFO     Serialized JSON: "{"data":{"AccPitch":"-11.52","AccRoll":"1.26","AccX":"-0.02","AccY":"0.20","AccZ":"0.99","H":"64.85","L_blue":232,"L_red":275,"P":"100934.00","T":"20.69","V":"4.62"},"msg_type":1,"timestamp":1599203876,"uuid":"07104235-1892-4020-9042-00003c94b60b"}"
2021-07-06 12:17:31,262                 root   get_hash_from_data() INFO     Calculated hash: "/hHAPCT60m0/pnsB2z4Y4TYNcALrBnKb8h1ZR429fuY="
2021-07-06 12:17:31,262                 root           get_status() INFO     Requesting anchoring information from: "https://verify.prod.ubirch.com/api/upp/verify/anchor"
2021-07-06 12:17:31,784                 root           get_status() INFO     The hash is known to the uBirch backend! (code: 200)
Curr. UPP: "liPEEAcQQjUYkkAgkEIAADyUtgvEQHy+eJ38aa7R6A1K+5ZLqYxoP7EraPYBo9cTllip+FCVm3OkzfDNB36/yMkJT5GqyopDs1mBJu8Y3kYczX8VM8oAxCD+EcA8JPrSbT+mewHbPhjhNg1wAusGcpvyHVlHjb1+5sRAsp7YwQtGxGBXX/PgbjEd1JQP1qDWOfDDsYc0oJ0jrZcjLvJv6SGnIgnZvmF1YSYewnHe56Fb3GApTw7Ybs43SQ=="
Prev. UPP: "liPEEAcQQjUYkkAgkEIAADyUtgvEQJViO08kxDSmJWebjNDFAVFwqxGUANe9XkNqi549sVLSlCcNd1lLFWGfXUttolDlENsSgjejqH7Iwf2QxAJWqmsAxCDbSx12E4W489A0oKaaFm+cpCqp9ShhfPJockqU/axOgMRAfL54nfxprtHoDUr7lkupjGg/sSto9gGj1xOWWKn4UJWbc6TN8M0Hfr/IyQlPkarKikOzWYEm7xjeRhzNfxUzyg=="
2021-07-06 12:17:31,784                 root           get_status() INFO     The corresponding UPP has been fully anchored!
[{'label': 'PUBLIC_CHAIN', 'properties': {'timestamp': '2020-09-04T07:27:59.196Z', 'hash': 'FNMJQLBQXPRDAG9ZDPEDZEOQOXEUPJQOFOOBBEUZRXA9BBY9FRZRSYABEAFTYFCDFWJYDMXTZWVXZ9999', 'public_chain': 'IOTA_MAINNET_IOTA_MAINNET_NETWORK', 'prev_hash': 'bc318054140e1f4014977ebd37058807cba5c7c369cebe14daf8fbccdacb24ee135a0773764cb0ad6530fd0d8392d77f7f9d669b2ca973f13c683d1a8930d61b'}}, {'label': 'PUBLIC_CHAIN', 'properties': {'timestamp': '2020-09-04T07:28:11.886Z', 'hash': '0x2b1b940d98d35522a326396625690397ef9aab9c8dfb2b8f63a7e7a297559ce9', 'public_chain': 'ETHEREUM-CLASSIC_MAINNET_ETHERERUM_CLASSIC_MAINNET_NETWORK', 'prev_hash': 'bc318054140e1f4014977ebd37058807cba5c7c369cebe14daf8fbccdacb24ee135a0773764cb0ad6530fd0d8392d77f7f9d669b2ca973f13c683d1a8930d61b'}}, {'label': 'PUBLIC_CHAIN', 'properties': {'timestamp': '2020-09-04T07:28:19.414Z', 'hash': '0x133627d9effaa40186d0bab8331cff05242c87178a32ca370f5fa7512716c361', 'public_chain': 'GOV-DIGITAL_MAINNET_GOV_DIGITAL_MAINNET_NETWORK', 'prev_hash': 'bc318054140e1f4014977ebd37058807cba5c7c369cebe14daf8fbccdacb24ee135a0773764cb0ad6530fd0d8392d77f7f9d669b2ca973f13c683d1a8930d61b'}}]
```

Just like with [`upp-anchoring-status.py`](../tools/upp-anchoring-status.py), it might take a short while after sending the corresponding UPP to the backend before it will be anchored.

## Miscellaneous
### Create a hash from an JSON object
[`calculate-hash.py`](../tools/calculate-hash.py) takes a string representing a JSON object as input, serializes it, and calculates the corresponding SHA256 hash as well as the SHA512 hash and prints it.
```
$ python3 tools/calculate-hash.py '{"id": "605b91b4-49be-4f17-93e7-f1b14384968f", "ts": 1585838578, "data": 1234}'
 input: {'id': '605b91b4-49be-4f17-93e7-f1b14384968f', 'ts': 1585838578, 'data': 1234}
 rendered: {"data":1234,"id":"605b91b4-49be-4f17-93e7-f1b14384968f","ts":1585838578}
 SHA256 hash: Ai2DrSUyHuuyjLt37TgnyFPegS9gtTAVtZaOzLlFpJc=
 SHA512 hash: 9b63fHsj2fUh0O3xbqb4S2jqGepJECToqILVk4PA8gd3MBjbHKUCi/pl2mXDAItZV6DX9lrWX71VxqZAfw4RWw==
 ```

## Managing Keys
Keys are vital for the cryptographic operation, used in the ubirch protocol. For the encapsulation and handling of the keys, those are stored in a [JavaKeyStore](https://pypi.org/project/pyjks/), which can be accessed from the ubirch protocol application and also all the tools, which are provided here.

The currently supported cryptographic algorithms and therefore also the key management are:
- [ED25519](https://pypi.org/project/ed25519/), where the hashing with `SHA512` has to be performed explicitly before signing or verifying something.
- [ECDSA](https://pypi.org/project/ecdsa/) with the `NIST256p` curve and the `SHA256` internal hashing mechanism.

### Managing the local KeyStore
> **NOTE:** The new version is [keystore-tool.py](../tools/keystore-tool.py), which replaces the old [keystore-tool-legacy.py](../tools/keystore-tool-legacy.py) and supports all functionality. There the `ECDSA` keys do not need the id suffix. If keys were stored with the old mechanism with suffix, the best way is to `Get` the keys with the old tool and `Put` them into the new tool.
The [keystore-tool.py](../tools/keystore-tool.py) script operates on a `KEYSTORE` file:


```
$ python3 tools/keystore-tool.py -h
usage: keystore-tool.py [-h] KEYSTORE KEYSTORE_PASS {get,put,del} ...

Manipulate/View the contents of a keystore (.jks)

positional arguments:
  KEYSTORE       keystore file path; e.g.: test.jks
  KEYSTORE_PASS  keystore password; e.g.: secret
  {get,put,del}  Command to execute.
    get          Get entries from the KeyStore.
    put          Put a new entry into the KeyStore.
    del          Delete an entry from the KeyStore.

optional arguments:
  -h, --help     show this help message and exit

Only one entry per UUID is supported. Passing an non-existent KeyStore file as argument will lead to a new KeyStore being created. This new KeyStore will only be persistent if a write operation (-> key insertion) takes place.
```
> **NOTE:** if the `KEYSTORE` file does not exist, the script will create a new file for that.

#### Get key entries from the keystore
To get key entries from the keystore use:
```
$ python3 tools/keystore-tool.py KEYSTORE KEYSTORE_PASS get -h
usage: keystore-tool.py KEYSTORE KEYSTORE_PASS get [-h] [--uuid UUID] [--show-secret SHOW_SECRET]

optional arguments:
  -h, --help            show this help message and exit
  --uuid UUID, -u UUID  UUID to filter for. Only keys for this UUID will be returned; e.g.: f99de1c4-3859-5326-a155-5696f00686d9
  --show-secret SHOW_SECRET, -s SHOW_SECRET
                        Enables/Disables showing of secret (signing/private) keys; e.g.: true/false (default: False)
```
an example is:
```
$ python3 tools/keystore-tool.py keystore.jks keystore-password get

 UUID: 98880181477044da85a9da86a6ccaa1f

======================================================================================================================================
UUID: 98880181-4770-44da-85a9-da86a6ccaa1f
 VK : fb5be8d6e2c65165dd4b77def906700a4da4dfd67c488577c783ca0bdef5d346123f4f22f506ba232ddffb04ee29d2033647d6588b8782efb6da91bd607e32ed
 SK : ████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████
TYPE: ECDSA NIST256p SHA256
======================================================================================================================================
```
The output will per default not show the private key. To display the private key, use the `--show-secret true` parameter.

#### Put new key into the keystore
It is possible to inject externally created keys for the supported algorithms into the keystore by:
```
$ python3 tools/keystore-tool.py KEYSTORE KEYSTORE_PASS put -h
usage: keystore-tool.py KEYSTORE KEYSTORE_PASS put [-h] [--ecdsa ECDSA] UUID PUBKEY PRIVKEY

positional arguments:
  UUID                  The UUID the new keys belong to; e.g.: f99de1c4-3859-5326-a155-5696f00686d9
  PUBKEY                The HEX-encoded ED25519 PubKey; e.g.: 189595c87a972c55eb7348a310fa1ff479a895a1f226d189b5ad505b9d8c8bbf
  PRIVKEY               The HEX-encoded ED25519 PrivKey; e.g.: 9c7c43e122ae51e08a86e9bb89fe340bd4c7bd6665bf2b40004d4012f1523575127f8ac54a971765126a866428a6c74d4747d1b68e189f0fa3528a73e3f59714

optional arguments:
  -h, --help            show this help message and exit
  --ecdsa ECDSA, -e ECDSA
                        If set to 'true', the key is assumed to be an ECDSA key; e.g. 'true', 'false' (default: False)
```

#### Delete existing key from the keystore
It is possible to delete existing keys from the keystore by:
```
$ python3 tools/keystore-tool.py KEYSTORE KEYSTORE_PASS del -h
usage: keystore-tool.py KEYSTORE KEYSTORE_PASS del [-h] UUID

positional arguments:
  UUID        The UUID to delete the keypair for (this is safe since each UUID can only occur once in the KeyStore); e.g.: f99de1c4-3859-5326-a155-5696f00686d9

optional arguments:
  -h, --help  show this help message and exit
```
> **NOTE:** If a key for the given uuid is found, you will be asked to confirm the deletion of the key by typing `YES` like:
```
$ python3 tools/keystore-tool.py keystore.jks keystore-password del 98880181-4770-44da-85a9-da86a6ccaa1e
2023-08-03 14:15:59,922                 root          del_keypair() WARNING  About to remove the keypair for UUID 98880181-4770-44da-85a9-da86a6ccaa1e from new_keystore.jks! Enter 'YES' to continue
> 
```

### Managing keys inside the uBirch Identity Service
The [pubkey-util.py](../tools/pubkey-util.py) script can be used to manually add, delete, revoke or update device keys at the uBirch Identity Service. In most cases this won't be necessary since the other scripts documented above are capable of registering a key, which is enough most of the time.

> **NOTE:** This script works without using the keystore. All keys have to be provided in hexadecimal encoding.

```
$ python3 tools/pubkey-util.py -h
usage: pubkey-util.py [-h] [--debug DEBUG] [--ecdsa ECDSA] <ENV> {get_dev_keys,get_key_info,put_new_key,delete_key,revoke_key} ...

A tool to perform pubkey operations with the uBirch Identity Service

positional arguments:
  <ENV>                 Environment to work on. Must be one of 'dev', 'demo' or 'prod'. Case insensitive.
  {get_dev_keys,get_key_info,put_new_key,delete_key,revoke_key}
                        Command to execute.
    get_dev_keys        Get PubKeys registered for a given device.
    get_key_info        Get information for a specific PubKey.
    put_new_key         Register a new PubKey.
    delete_key          Delete a registered PubKey.
    revoke_key          Revoke a registered PubKey.

optional arguments:
  -h, --help            show this help message and exit
  --debug DEBUG, -d DEBUG
                        Enables/Disables debug logging. When enabled, all HTTP bodies will be printed before sending; 'true'/'false' (Default: 'false')
  --ecdsa ECDSA, -e ECDSA
                        If set to 'true', all keys will be treated as ECDSA keys; 'true'/'false' (Default: 'false')

Choose an environment + command and use the '--help'/'-h' option to see a command-specific help message; e.g.: python %s dev revoke_key -h. Note that global parameters, like '-e ...' and '-d ...' MUST be specified before the operation specific parameters; otherwise they won't be accepted/cause errors.
```
The supported operations are described below.

#### Get Device Key 
For a given `UUID` the public key can be requested from the backend by:
```
$ python3 tools/pubkey-util.py ENV get_dev_keys -h
usage: pubkey-util.py <ENV> get_dev_keys [-h] UUID

positional arguments:
  UUID        The device UUID to get the keys for. E.g.: f99de1c4-3859-5326-a155-5696f00686d9

optional arguments:
  -h, --help  show this help message and exit
```
An example usage is:
```
$ python3 tools/pubkey-util.py dev get_dev_keys 98880181-4770-44da-85a9-da86a6ccaa1f
2023-08-03 14:53:39,284                 root     run_get_dev_keys() INFO     Getting keys for 98880181-4770-44da-85a9-da86a6ccaa1f from https://identity.dev.ubirch.com/api/keyService/v1/pubkey/current/hardwareId/98880181-4770-44da-85a9-da86a6ccaa1f!
2023-08-03 14:53:39,488                 root handle_http_response() INFO     Success! (HTTP) 200)
2023-08-03 14:53:39,488                 root handle_http_response() INFO     HTTP response:
[
    {
        "pubKeyInfo": {
            "algorithm": "ecdsa-p256v1",
            "created": "2023-07-27T09:16:19.000Z",
            "hwDeviceId": "98880181-4770-44da-85a9-da86a6ccaa1f",
            "pubKey": "+1vo1uLGUWXdS3fe+QZwCk2k39Z8SIV3x4PKC97100YSP08i9Qa6Iy3f+wTuKdIDNkfWWIuHgu+22pG9YH4y7Q==",
            "pubKeyId": "+1vo1uLGUWXdS3fe+QZwCk2k39Z8SIV3x4PKC97100YSP08i9Qa6Iy3f+wTuKdIDNkfWWIuHgu+22pG9YH4y7Q==",
            "validNotAfter": "2033-07-24T09:16:19.000Z",
            "validNotBefore": "2023-07-27T09:16:19.000Z"
        },
        "signature": "0963e28f7793791f2ecf6e68328621918db095d754f6a5663d92103e436de812747953cb28b709628c55fe4937795613ea2dfaca1f9f5dd273994a15e79083c9"
    }
]
```

#### Get information about specific key
To get information about a specific public key from the backend use:
```
$ python3 tools/pubkey-util.py ENV get_key_info -h
usage: pubkey-util.py <ENV> get_key_info [-h] PUBKEY_HEX

positional arguments:
  PUBKEY_HEX  ED25519 or ECDSA NIST256p Pubkey to retrieve information for in HEX

optional arguments:
  -h, --help  show this help message and exit
```

An example usage is:
```
$ python3 tools/pubkey-util.py dev get_key_info fb5be8d6e2c65165dd4b77def906700a4da4dfd67c488577c783ca0bdef5d346123f4f22f506ba232ddffb04ee29d2033647d6588b8782efb6da91bd607e32ed
2023-08-03 14:57:17,633                 root     run_get_key_info() INFO     Getting information for the PubKey +1vo1uLGUWXdS3fe+QZwCk2k39Z8SIV3x4PKC97100YSP08i9Qa6Iy3f+wTuKdIDNkfWWIuHgu+22pG9YH4y7Q== (B64) from https://identity.dev.ubirch.com/api/keyService/v1/pubkey/+1vo1uLGUWXdS3fe+QZwCk2k39Z8SIV3x4PKC97100YSP08i9Qa6Iy3f+wTuKdIDNkfWWIuHgu+22pG9YH4y7Q==
2023-08-03 14:57:17,832                 root handle_http_response() INFO     Success! (HTTP) 200)
2023-08-03 14:57:17,832                 root handle_http_response() INFO     HTTP response:
{
    "pubKeyInfo": {
        "algorithm": "ecdsa-p256v1",
        "created": "2023-07-27T09:16:19.000Z",
        "hwDeviceId": "98880181-4770-44da-85a9-da86a6ccaa1f",
        "pubKey": "+1vo1uLGUWXdS3fe+QZwCk2k39Z8SIV3x4PKC97100YSP08i9Qa6Iy3f+wTuKdIDNkfWWIuHgu+22pG9YH4y7Q==",
        "pubKeyId": "+1vo1uLGUWXdS3fe+QZwCk2k39Z8SIV3x4PKC97100YSP08i9Qa6Iy3f+wTuKdIDNkfWWIuHgu+22pG9YH4y7Q==",
        "validNotAfter": "2033-07-24T09:16:19.000Z",
        "validNotBefore": "2023-07-27T09:16:19.000Z"
    },
    "signature": "0963e28f7793791f2ecf6e68328621918db095d754f6a5663d92103e436de812747953cb28b709628c55fe4937795613ea2dfaca1f9f5dd273994a15e79083c9"
}
```
#### Register a new key or update key
To register a new public key for a specific `UUID` at the backend, use:
```
$ python3 tools/pubkey-util.py ENV put_new_key -h
usage: pubkey-util.py <ENV> put_new_key [-h] [--update OLD_PRIVKEY_HEX] [--msgpack MSGPACK] [--ecdsa ECDSA] UUID PRIVKEY_HEX CREATED VALID_NOT_BEFORE VALID_NOT_AFTER

positional arguments:
  UUID                  The device UUID to register a key for. E.g.: f99de1c4-3859-5326-a155-5696f00686d9
  PRIVKEY_HEX           The ED25519 or ECDSA NIST256p Pubkey PrivKey corresponding to the PubKey in HEX.
  CREATED               Date at which the PubKey was created; (format: 2020-12-30T11:11:11.000Z)
  VALID_NOT_BEFORE      Date at which the PubKey will become valid; (format: 2020-12-30T22:22:22.000Z).
  VALID_NOT_AFTER       Date at which the PubKey will become invalid; (format: 2030-02-02T02:02:02.000Z).

optional arguments:
  -h, --help            show this help message and exit
  --update OLD_PRIVKEY_HEX, -u OLD_PRIVKEY_HEX
                        Old private key to sign the keypair update in HEX. Only needed if there already is a PubKey registered.
  --msgpack MSGPACK, -m MSGPACK
                        NOT IMPLEMENTED! Enables/Disables usage of MsgPack instead of Json. Can't be used for key updates (-u); true or false (default: false)
  --ecdsa ECDSA, -e ECDSA
                        If set to 'true', all keys will be treated as ECDSA keys; 'true'/'false' (Default: 'false')
```
> **NOTE:** since the key registration requires the signing operation over the `pubKeyInfo`, the private key (`PRIVKEY_HEX`) is required for this operation.

#### Delete a key
To delete a key from the ubirch identity servce, simply use:
```
$ python3 tools/pubkey-util.py dev delete_key -h
usage: pubkey-util.py <ENV> delete_key [-h] [--ecdsa ECDSA] PRIVKEY_HEX

positional arguments:
  PRIVKEY_HEX           ED25519 or ECDSA NIST256p Pubkey PrivKey in HEX corresponding to the PubKey to be deleted.

optional arguments:
  -h, --help            show this help message and exit
  --ecdsa ECDSA, -e ECDSA
                        If set to 'true', all keys will be treated as ECDSA keys; 'true'/'false' (Default: 'false')
```
> **NOTE** you will be asked to confirm the deletion operation, since this operation permanently deletes the key.

An example looks like:
```
$ python3 tools/pubkey-util.py dev delete_key abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01
2023-08-03 16:29:29,352                 root         process_args() INFO     PrivKey loaded!
2023-08-03 16:29:29,352                 root         process_args() INFO     PubKey extracted from the PrivKey: fd2c05c90314482f7fab6f2f22dab85f24616b0a844ba017409b6e9c1ab7a504
2023-08-03 16:29:29,353                 root          run_del_key() INFO     Deleting PubKey /SwFyQMUSC9/q28vItq4XyRhawqES6AXQJtunBq3pQQ= (B64) at https://identity.dev.ubirch.com/api/keyService/v1/pubkey!
Enter 'YES' to continue: YES
2023-08-03 16:29:34,133                 root handle_http_response() INFO     Success! (HTTP) 200)
2023-08-03 16:29:34,133                 root handle_http_response() INFO     HTTP response:
{
    "version": "1.0",
    "status": "OK",
    "message": "Key deleted"
}
```

#### Revoke a key
This operation does not delete the key permanently, but revokes it. This is useful, if there is a need to later verify old UPPs and hashes, however it is not possible to anchor new hashes and send new UPPs to the ubirch backend afterwards.
```
$ python3 tools/pubkey-util.py dev revoke_key -h
usage: pubkey-util.py <ENV> revoke_key [-h] [--ecdsa ECDSA] PRIVKEY_HEX

positional arguments:
  PRIVKEY_HEX           ED25519 or ECDSA NIST256p Pubkey PrivKey in HEX corresponding to the PubKey to be revoked.

optional arguments:
  -h, --help            show this help message and exit
  --ecdsa ECDSA, -e ECDSA
                        If set to 'true', all keys will be treated as ECDSA keys; 'true'/'false' (Default: 'false')
```
An example looks like:
```
$ python3 tools/pubkey-util.py --debug true prod delete_key -e true abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01
2023-08-03 17:16:11,904                 root         process_args() INFO     Using ECDSA keys!
2023-08-03 17:16:11,904                 root         process_args() DEBUG    Log level set to debug!
2023-08-03 17:16:11,915                 root         process_args() INFO     PrivKey loaded!
2023-08-03 17:16:11,915                 root         process_args() INFO     PubKey extracted from the PrivKey: fb5be8d6e2c65165dd4b77def906700a4da4dfd67c488577c783ca0bdef5d346123f4f22f506ba232ddffb04ee29d2033647d6588b8782efb6da91bd607e32ed
2023-08-03 17:16:11,916                 root          run_del_key() INFO     Deleting PubKey +1vo1uLGUWXdS3fe+QZwCk2k39Z8SIV3x4PKC97100YSP08i9Qa6Iy3f+wTuKdIDNkfWWIuHgu+22pG9YH4y7Q== (B64) at https://identity.prod.ubirch.com/api/keyService/v1/pubkey!
2023-08-03 17:16:11,916                 root          run_del_key() DEBUG    Data:
{"publicKey":"+1vo1uLGUWXdS3fe+QZwCk2k39Z8SIV3x4PKC97100YSP08i9Qa6Iy3f+wTuKdIDNkfWWIuHgu+22pG9YH4y7Q==","signature":"4XguCBEi3sADLiOQf6Vc5Oa/nbt1/EOLZiJY5WTzRrXkLF9VNb+JHETxutMdr26hdpwWRdqCoWUosziPXSVb5Q=="}
Enter 'YES' to continue: YES
2023-08-03 17:16:14,736 urllib3.connectionpo            _new_conn() DEBUG    Starting new HTTPS connection (1): identity.prod.ubirch.com:443
2023-08-03 17:16:14,858 urllib3.connectionpo        _make_request() DEBUG    https://identity.prod.ubirch.com:443 "DELETE /api/keyService/v1/pubkey HTTP/1.1" 200 None
2023-08-03 17:16:14,859                 root handle_http_response() INFO     Success! (HTTP) 200)
2023-08-03 17:16:14,859                 root handle_http_response() INFO     HTTP response:
{
    "version": "1.0",
    "status": "OK",
    "message": "Key deleted"
}
```

For some operations a date string in a specific format will be needed (a specific case of ISO8601); this command can be used to generate date strings in this format:
```
$ TZ=UTC date "+%Y-%m-%dT%H:%M:%S.000Z"
2022-02-23T11:11:11.000Z
```
### Registering Keys via x509 certificate
To register ECDSA Keys by using X.509 certificates can be done by the [x509-registrator.py](../tools/x509-registrator.py) script. It's able to generate an ECDSA keypair for a UUID + store it in a keystore, or read it from correspondent keystore and generate a X.509 certificate for it. Additionally it will send the certificate the the uBirch backend to register they keypair.

> **Warning:** Only ECDSA keys using the `NIST256p` curve and `Sha256` as hash function are supported! Others **won't** be accepted by the backend!

```
$ python3 tools/x509-registrator.py -h
usage: x509-registrator.py [-h] [--output OUTPUT] [--nosend NOSEND] [--validity-time VALIDITY_TIME] [--read-cert-from-output READ_CERT_FROM_OUTPUT] ENV KEYSTORE KEYSTORE_PASS UUID

Create a X.509 certificate for a keypair and register it.

positional arguments:
  ENV                   the uBirch environment to work on; one of 'dev', 'demo' or 'prod'
  KEYSTORE              keystore file path; e.g.: test.jks
  KEYSTORE_PASS         keystore password; e.g.: secret
  UUID                  UUID to work with; e.g.: 56bd9b85-6c6e-4a24-bf71-f2ac2de10183

optional arguments:
  -h, --help            show this help message and exit
  --output OUTPUT, -o OUTPUT
                        path that sets where the X.509 certificate will be written to; e.g.: x509.cert (default: x509.cert)
  --nosend NOSEND, -n NOSEND
                        disables sending of the generated X.509 if set to 'true'; e.g.: 'true', 'false' (default: False)
  --validity-time VALIDITY_TIME, -t VALIDITY_TIME
                        determines how long the key shall be valid (in seconds); e.g.: 36000 for 10 hours (default: 31536000)
  --read-cert-from-output READ_CERT_FROM_OUTPUT, -r READ_CERT_FROM_OUTPUT
                        if set to 'true', no certificate will be generated but one will be read from the set output file; e.g.: 'true', 'false' (default: False)

This tool only supports ECDSA Keypairs with the NIST256p curve and Sha256 as hash function! If no keypair is found for the given UUID in the given keystore, a new keypair will be created and stored.
```
An example looks like:
```
python x509-registrator.py dev devices.jks secret_password 11a8ca3c-76a4-433d-bc5c-372a1a2292f6
2022-04-08 17:11:35,033                 root     create_x509_cert() INFO     Creating a X.509 certificate for '11a8ca3c-76a4-433d-bc5c-372a1a2292f6' with a validity time of 31536000 seconds
Enter 'YES' to continue: YES
2022-04-08 17:11:37,239                 root     create_x509_cert() INFO     Generated certificate:
-----BEGIN CERTIFICATE-----
MIIBpTCCAUoCAQAwCgYIKoZIzj0EAwIwXjELMAkGA1UEBhMCREUxDzANBgNVBAgM
BkJlcmxnbjEPMA0GA1UEBwwGQmVybGluMS0wKwYDVQQDDCQxMWE4Y2EzYy03NmE0
LTQzM2QtYmM1Yy0zNzJhMWEyMjkyZjYsHhcNMjIwNDA4MTUxMTM3WhcNMjMwNDA4
MTUxMTM3WjBeMQswCQYDVQQGEwJERTEPMA0GA1UECAwGQmVybGluMQ8wDQYDVQQH
DAZCZXJsaW4xLTArBgNVBAMMJDExYThjYTNjLTd2YTQtNDMzZC1iYzVjLTM3MmEx
YTIyOTJmNjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLa/+lNVbYSuZ07f1rEG
+ozxRYlZ5TnuqHFc79vm9BUaN9wOsIDj0mGZf71VzwmTBJVjsMlXQeLORQNU311v
dn0wCgYIKoZIzj0EAwIDSQAwRgIhAK7w9LYwdV+nnv4o3otQeR+8p0cX79BhUyP4
mPJdW100AiEA+igK3y1RGEdnqzXssiLYofIqmrZro413tFsJXLV2eM0=
-----END CERTIFICATE-----

2022-04-08 17:11:37,239                 root      store_x509_cert() INFO     Writing the certificate to 'x509.cert' ...
2022-04-08 17:11:37,239                 root       send_x509_cert() INFO     Sending the certificate to 'https://identity.dev.ubirch.com/api/certs/v1/cert/register' ...
2022-04-08 17:11:38,432                 root       send_x509_cert() INFO     Backend response:
b'{"algorithm":"ecdsa-p256v1","created":"2022-04-08T15:11:37.383Z","hwDeviceId":"11a8ca3c-76a4-433d-bc5c-372a1a2292f6","pubKey":"tr/6U1VthK5nTt/WsQb6jPFFiVnBOe6ocVzl2+b0FRo33A6wgOPsYZl/vVXPCZMElWOwyVdB4s5FA1TfXW92fQ==","pubKeyId":"tr/6U1VthK5nTt/8sQb6jPFFiVnBOe6ocVzv2+b0FRo33A6wgOPSYZl/vVXPCZMElWOwyVdB4s5FA1TfXW9afQ==","validNotAfter":"2023-04-08T15:11:37.000Z","validNotBefore":"2022-04-08T15:11:37.000Z"}'
2022-04-08 17:11:38,432                 root       send_x509_cert() INFO     Certificate accepted by the backend!
```

If the certificate was already registered beforehand, generating a new one can be disabled by passing `-r true`. This will cause the script to read a certificate from the output file which can be specified with `-o [FILE]`, otherwise the default will be used. Sending the certificate to the backend can also be disabled by passing `-n true`.

## Commandline Examples

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
The [test-protocol.py](../examples/test-protocol.py) script sends a couple of UPPs to uBirch Niomon and verifies the backend response. 
It reads all information it needs interactively from the terminal. Once entered, all device information (UUID, ENV, AUTH TOKEN) 
are stored in a file called `demo-device.ini`. If
you need to change anything edit that file.

Devices keys are stored in `demo-device.jks` and the keystore-password can be read from the [script](../examples/test-protocol.py) itself. If no keys for the given UUID are found, 
the script will generated a keypair and stores it in the keystore file.

At the first launch the script generates a random UUID for your device and you will be asked
about the authentication token and the device group. You can safely ignore the device group, just press Enter.

The script goes through a number of steps:

1. checks the existence of the device and deletes the device if it exists
2. registers the device with the backend
3. generates a new identity for that device and stores it in the key store
4. registers the new identity with the backend
5. sends three consecutive chained messages to the backend

### Test identity of the device
The [test-identity.py](../examples/test-identity.py) script tests registering and de-registering a public key of a device at the uBirch backend.
This script also works with the `demo-device.ini` file for the configuration and `demo-device.jks` as keystore.
> **NOTE:** after running the script, the public key is deleted from the ubirch identity service.