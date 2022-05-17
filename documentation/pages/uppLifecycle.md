@page uppLifecycle A UPP's Lifecycle
@tableofcontents

<!-- These markdown files are supposed to be read by doxygen, 
a software for generating documentation. So don't wonder about the @page, 
@ref - or similar statements. Please refer as well to the 
official documentation at developer.ubirch.com -->



## From measurement to blockchain-anchored UPP
The process needed to get a UPP to be anchored in the blockchain can be cut down into multiple steps. 
For each of those steps there is an example in this directory, demonstrating how to handle them.

### Generating and managing a keypair
To create, or more precisely, to _sign_ a UPP, a device will need a keypair. This keypair consist of a private key (_signing key_) and public key (_verifying key_). 

The signing key is used to sign UPPs and the verifying key can be used by the uBirch backend to check, if the signature is valid and belongs to the correct sender/signer. So, logically it doesn't matter who knows the verifying key, but the signing key must be kept secret all the time. 

In a real use case a device might store it in a TPM ([Trusted platform module](https://en.wikipedia.org/wiki/Trusted_Platform_Module)) or use other counter measures against attackers reading the key from the device. For this demo, keypairs will be stored in a [JKS Keystore](https://en.wikipedia.org/wiki/Java_KeyStore) using the [`pyjks`](https://pypi.org/project/pyjks/) library. Therefore, you will have to choose and remember a file path for that keystore and a password used to encrypt it. The process of actually generating the keypair is handled by the [upp-creator.py](upp-creator.py) script and explained [below](#registering-a-public-key).

To read generated keys from the KeyStore, see [below](#managing-the-local-keystore).

@note Loosing access to the signing key, especially if it is already registered at the uBirch backend, will take away the ability to create and send any new UPPs from that device/UUID, since there is no way of creating a valid signature that would be accepted by the backend.

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
Translated to a hypothetical use case this could be a measurement taken at `1625163338` (Unix-Timestamp), stating that the sensor measured `11.2 C` in temperature (`T`) and `35.8 %H` in humidity (`H`). The  status - `S` - is `'OK'`. There is no script for this step, since it can easily be done by hand.

### Data Format
**Note:**
If you use a JSON format for your data, the data has to be alphabetically sorted, all whitespace removed and 
serialized into a simple string, before the hash of the data is generated. This ensures, that you can always regenerate
the same hash for your data. This is already implemented in the examples, like the following lines of code show:
```python
message = '{"ts": 1625163338, "T": 11.2, "H": 35.8, "S": "OK" }'
serialized = json.dumps(message, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode()
```
This will create a string from the above examplary JSON object:
`b'{"H":35.8,"S":"OK","T":11.2,"ts":1625163338}'`

### Creating a UPP
After gathering some measurement data a UPP can be created. The UPP won't contain the actual measurement data, but a hash of it. The example script to create UPPs is [`upp-creator.py`](upp-creator.py).
```
$ python3 upp-creator.py --help

usage: upp-creator.py [-h] [--version VERISON] [--type TYPE] [--ks KS] [--kspwd KSPWD] [--keyreg KEYREG] [--hash HASH] [--isjson ISJSON] [--output OUTPUT] [--nostdout nostdout] UUID DATA

Note that, when using chained UPPs (--version 0x23), this tool will try to load/save signatures from/to <UUID>.sig, where UUID will be replaced with the actual UUID. Make sure that the UUID.sig file is in your current working directory if you try to continue a UPP chain using this tool. Also beware that you will only be able to access the contents of a keystore when you use the same password you used when creating it. Otherwise all contents are lost. When --hash off is set, contents of the DATA argument will be copied into the payload field of the UPP. Normally used for special messages (e.g. key registration). For more information on possible values for --type and --version see https://github.com/ubirch/ubirch-protocol.
```
The script allows multiple modes of operation, which can be set through different command line arguments. Some of those directly set fields in the resulting UPP. Please consult the [uBirch Protocol Readme](https://github.com/ubirch/ubirch-protocol#basic-message-format) for further information on those fields and their possible values.
- `--version/-v` This flag sets the version field of the UPP. The version field actually consists of two sub-fields. The higher four bits set the actual version (`1` or `2`) and the "mode". The higher four bits will be set to two(`0010`) in almost all use cases. The mode can either be a simple UPP without a signature, a UPP with a signature and a UPP with a signature + the signature of the previous UPP embedded into it. The latter would be called a_Chained UPP_. Unsigned UPPs (`-v 0x21`) are not implemented. Signed UPPs have `-v 0x22` and chained ones `-v 0x23`.
- `--type/-t` This flag sets the type field of the UPP. It is used to indicate what the UPP contains/should be used for. It can be set to `0x00` in most cases. One of the cases where a specific value is required, is a Key Registration Messages, as described in [Registering a Public Key](#registering-a-public-key).
- `--k/-k` The path to the keystore that contains the keypair for the device or should be used to store a newly generated keypair. If the keystore, pointed to by this parameter, doesn't exist, the script will simply create it.
- `--kspwd/-p` The password to decrypt/encrypt the keystore. You must remember this, or you will lose access to the keystore and all its contents.
- `--keyreg/-k` Tells the script that the UPP that should be generated is a key registration UPP. The effect of that is that the script will ignore any custom input data and the `--hash` parameter (below). Instead, the UPP will contain the public key certificate. This parameter is a binary flag which can have two values: `true` or `false`.
- `--hash` Sets the hash algorithm to be used to generate the hash of the input data. The produced hash will then be inserted into the payload field of the UPP. This parameter can have three values: `sha512`, `sha256` and `off`. When set to off, the input data will be directly put into the UPP without hashing it. This is only useful in some special cases like when manually assembling key registration messages (normally the `--keyreg` option should be used for that).
- `--isjson/-j` A binary flag that indicates that the input data is in JSON format. The script will serialize the JSON object before calculating the hash. This has the advantage one doesn't have to remember the order in which fields are listed in a JSON object to still be able to reconstruct the hash later on. Serializing the JSON is done like explained above in [Data Format](#data-format). This flag can have two values: `true` or `false`.
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
Keep in mind that if you use chained UPPs (`--version 0x23`) you should anchor each UPP, or the signature chain will be broken. This won't cause any errors, but the advantage of chaining UPPs and thereby knowing the correct order of them, will get lost.

### Sending a UPP
After creating the UPP, it can be sent to the uBirch backend where it will be verified and anchored in the blockchain. The ubirch backend will use the registered public/verifying key to check the signature. The [`upp-sender.py`](upp-sender.py) script can be used for that.
```
$ python3 upp-sender.py --help
usage: upp-sender.py [-h] [--env ENV] [--input INPUT] [--output OUTPUT] UUID AUTH
```
For this script the parameters are:
- `--env/-e` The env to operate on. This parameter decides wether the UPP will be sent to `niomon.prod.ubirch.com`, `niomon.demo.ubirch.com` or `niomon.dev.ubirch.com`. The value can either be `prod`, `demo` or `dev`. It must match the stage, the UUID is registered on.
- `--input/-i` Specifies where to read the UPP to be sent from. This can be a normal file path or also `/dev/stdin`, if for example the UPP will be piped to this script from another script (like [`upp-creator.py`](upp-creator.py)). In most cases the UPP will just be read from some file.
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
To make sure, that the response UPP actually was sent by the uBirch backend, its signature can be checked. The example script for that is [`upp-verifier.py`](upp-verifier.py). It knows the UUID and verifying/public key for each uBirch Niomon stage end checks, if the signature of the response UPP is valid.

```
$ python3 upp-verifier.py --help
usage: upp-verifier.py [-h] [--verifying-key VK] [--verifying-key-uuid UUID] [--input INPUT]

Note that, when trying to verify a UPP, sent by the uBirch backend (Niomon), a verifying key doesn't have to be provided via the -k option. Instead, this script will try to pick the correct stage key based on the UUID which is contained in the UPP, identifying the creator. If the UUID doesn't match any Niomon stage and no key was specified using -k, an error message will be printed.
```
- `--verifying-key/-k` If not trying to verify a UPP coming from uBirch Niomon but from another source, the verifying key for that source needs to be provided. This parameter expects the key as a hex-string like `b12a906051f102881bbb487ee8264aa05d8d0fcc51218f2a47f562ceb9b0d068`.
- `--verifying-key-uuid/-u` The UUID for the verifying key from `--verifying-key`. This parameter will be ignored when `--verifying-key` is not set. Not setting this parameter when `--verifying-key` is set will cause an error.
- `--input/-i` The file path to read the UPP from.

```
$ python3 upp-verifier.py --input response_upp.bin
2021-07-02 15:43:36,273                 root             read_upp() INFO     Reading the input UPP from "response_upp.bin"
2021-07-02 15:43:36,274     ubirch.ubirch_ks           _load_keys() WARNING  creating new key store: -- temporary --
2021-07-02 15:43:36,274                 root         get_upp_uuid() INFO     UUID of the UPP creator: "07104235-1892-4020-9042-00003c94b60b"
2021-07-02 15:43:36,275                 root           verify_upp() INFO     Signature verified - the UPP is valid!
```

### Verifying a UPP chain
When working with `chained UPPs` it can be useful to check whether the chain is in order and valid. For
this task, the [`upp-chain-checker.py`](upp-chain-checker.py) can be used. It reads in a list of UPPs,
checks the signature of each UPP and compares the `prevsig` field with the `signature` of the last UPP.
If at any point something doesn't match up, it will print an error message along with the number of the
UPP at which the chain broke/something went wrong. The UPP list can either be read directly from a file
which contains them in binary or hex-encoded, separated by newlines, or from a JSON file which contains
a list of hex-encoded UPPs.
```
$ python3 upp-chain-checker.py -h
usage: upp-chain-checker.py [-h] [--is-json ISJSON] [--is-hex ISHEX] INPUTFILE VK UUID
```
The `VK` and `UUID` arguments work like in the [UPP-Verifier](#verifying-an-upp), with the difference
that they aren't optional and must be provided. Here is an example JSON file containing four UPPs
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
To examine the contents (Version Field, Type Field, UUID, Signature, Payload, Previous Signature) of a UPP, the [`upp-unpacker.py`](upp-unpacker.py) script can be used like this:
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

### Checking the anchoring status of a UPP
uBirch Niomon accepting the UPP doesn't mean that it is anchored yet. This process takes place in certain intervals, so one might have to wait a short while. The script to check if a UPP was already anchored is [`upp-anchoring-status.py`](upp-anchoring-status.py).
```
$ python3 upp-anchoring-status.py -h
usage: upp-anchoring-status.py [-h] [--ishash ISHASH] [--env ENV] [--ishex ISHEX] INPUT
```
- `--ishash/-i` A boolean specifying whether the input data is a payload hash or a UPP. The payload hash is what is actually used to look up anchoring information about the UPP. This script can either extract it from a given UPP or just use the hash directly if provided. If directly provided, it must be base64 encoded (see the last example of this sub-section). `true` or `false`.
- `--env/-e` The stage to check on. Should be the one the UPP was sent to. `prod`, `demo` or `dev`.
- `--ishex/-x` A boolean which controls how the input UPP data is interpreted. By default, the data will
be interpreted as normale binary data. When this flag is set to `true`, it will be considered
hex-encoded binary data and de-hexlified before parsing it.
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

**Note** that when running on `prod` the output regarding the anchoring status will be significantly more detailed:
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