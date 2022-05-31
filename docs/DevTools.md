
# Developer Tools

This file documents how to use the tools provided alongside the [uBirch-Protocol-Python](https://github.com/ubirch/ubirch-protocol-python), which can be found in `/tools/`. 

The tools use the Ubirch library, which is implemented in the `/ubirch/` directory in this repository. 

Those tools aim to be useful when getting started and to provide an insight of how to use the components. All of them are commandline tools who have to be given API Credentials.

**Feel free to peek inside the sourcecode!**

### Setup - API Credentials
Make sure to follow the steps in [Quickstart](Quickstart.md) first.

You should have the following information at hand:
- The stage you want to work on (later referred to as `env`)
- The UUID of your device or "fake" device in this instance
- The authentication token (`auth token`) for the named UUID

The values used below are `f5ded8a3-d462-41c4-a8dc-af3fd072a217` for the UUID, `demo` for the env and
`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` for the auth token.



### Verifying data
In a real use case, not the UPP, but rather the original data itself has to be verified. The original data can be hashed, and the hash can be looked up by the [`data-verifier.py`](data-verifier.py) script. It has similar behaviour to the [`upp-anchoring-status.py`](upp-anchoring-status.py) script, see [Checking the anchoring status of a UPP](#checking-the-anchoring-status-of-an-upp).
```txt
$ python data-verifier.py --help
usage: data-verifier.py [-h] [--ispath ISPATH] [--env ENV] [--isjson ISJSON] [--hash HASH] [--no-send NOSEND] [--ishl ISHASHLINK] INPUT
```
- `--ispath/-i` Specifies wether the input is to be treated as a data-file path or direct input data. `true` or `false`.
- `--env-e` The stage to check on. Should be the one the UPP corresponding to the data was sent to. `prod`, `demo` or `dev`.
- `--isjson/-j` A binary flag that indicates that the input data is in JSON format. The script will serialize the JSON object before calculating the hash. This has the advantage one doesn't have to remember the order in which fields are listed in a JSON object to still be able to reconstruct the hash later on. Serializing the JSON is done like explained above in [Data Format](#data-format). This flag can have two values: `true` or `false`. It should only be set to `true` if the data represents a JSON object and if it also was serialized when creating the UPP.
- `--hash/-a` Sets the hashing algorithm to use. `sha256`, `sha512` or `off`. It should match the algorithm used when creating the corresponding UPP. Setting it to `off` means that the input data actually already is the hash of the data. In this case this script will simply look up the hash.
- `--ishl/-l` enables Hashlink functionality. This means that the script will expect the input data to be a valid JSON object and to contain a list called `hashLink` at root-level. This list contains the names of all fields that should be taken into account when calculating the hash. Different JSON-levels can are represented like this: `[..., "a.b", ...]`.

Example for CLI-Input data:
```txt
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
Curr. UPP: "liPEEPXe2KPUYkHEqNyvP9ByohfEQMvoTzPB2AqaKmjxDGHIQ1ZwNdGReacDu14K/06SDZuFNayxcfH9VScTcdGZ/JhfM88LMfPG7Pp75oS1YaxtkA8AxCB19C7vAEIvZoK4CpYuTIcRcLNOUod18yvs8yvERzBjoMRAzMfjnZoay
 /OdMH0I1bX3QhgBbguedNHvx2QMVAxM2hvxgrOJp+2f0/77BHzmz1E90aBHGT7QoTEQ9yf+9EIRAg=="
Prev. UPP: "None"
2021-07-02 16:21:41,600                 root           get_status() INFO     The corresponding UPP has been fully anchored!
[{'label': 'PUBLIC_CHAIN', 'properties': {'timestamp': '2021-07-02T13:23:30.076Z', 'hash': '0x6e5956b4ac53bcaf58664e189673d4f8c7043488cf05009cc96868b146220604', 'public_chain': 'ETHEREUM-CLASSIC_TESTNET_ETHERERUM_CLASSIC_KOTTI_TESTNET_NETWORK', 'prev_hash': '644b41eee9043de5bda4b58bda1136fa0229712953678fe26486651338109b7a7135211f2b2cb646ab25d3b25198549e3c662c4791d60d343f08349b51ccc92b'}}]
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

Just like with [`upp-anchoring-status.py`](upp-anchoring-status.py), it might take a short while after sending the corresponding UPP to the backend before it will be anchored.

## Miscellaneous
### Create a hash from an JSON object
[`create-hash.py`](create-hash.py) takes a string representing a JSON object as input, serializes it, and calculates the corresponding SHA256 hash.
```
$ python3 create-hash.py '{"ts": 1625163338, "T": 11.2, "H": 35.8, "S": "OK"}'
   input: {"ts": 1625163338, "T": 11.2, "H": 35.8, "S": "OK"}
rendered: {"H":35.8,"S":"OK","T":11.2,"ts":1625163338}
    hash: dfQu7wBCL2aCuAqWLkyHEXCzTlKHdfMr7PMrxEcwY6A=
```

###
### Verify ECDSA signed UPP
The [`verify-ecdsa.py`](verify-ecdsa.py) script verifies a hard-coded UPP which was signed with an ECDSA signing key using a ECDSA verifying key. All the information are contained in the script.

###
### Verify ED25519 signed UPP
The [`verify-ed25519.py`](verify-ed25519.py) script verifies a hard-coded UPP which was signed with an ED25519 signing key using a ED25519 verifying key. All the information are contained in the script. This mode is normally used (in all other tools).

## Managing Keys
### Managing the local KeyStore
`keystore-tool.py` is a script to manipulate contents of JavaKeyStores (JKS) as they are used by other example scripts. It supports displaying Keypair, adding new ones and also deleting entries.
```
$ python keystore-tool.py --help
usage: keystore-tool.py [-h] KEYSTORE KEYSTORE_PASS {get,put,del} ...
```
Run `python keystore-tool.py a b get --help` to get a help message for the `get` operation. The first two arguments will be ignored in that case. `get` can be exchanges for `put` or `del` to get information about those operations respectively. One valid invocation of the script might look like this:
```
$ python keystore-tool.py devices.jks keystore get -u 55425678-1234-bf80-30b4-dcbabf80abcd -s true
```
It will search for an entry matching the given UUID (specified by `-u`) and print the corresponding KeyPair if found. The PrivateKey will also be shown (`-s true`).

**Note that once an entry is deleted, it is gone. It is recommended to keep backups of KeyStores containing important keys.**

### Managing keys inside the uBirch Identity Service
The `pubkey-util.py` script can be used to manually add, delete, revoke or update device keys at the uBirch Identity Service. In most cases this won't be necessary since the other scripts documented above are capable of registering a key, which is enough most of the time. In total, this script supports five operations:
```
get_dev_keys - Get all PubKeys registered for a given device. This won't include revoked or deleted keys.
get_key_info - Get information about a specific key (basically all information provided when registering it).
put_new_key  - Register a new key for a device that has no keys yet, or add a new one if it already has one.
delete_key   - Removes a key so that it can't be used/won't be recognized by the backend anymore.
revoke_key   - Revokes a key so that it can't be used anymore for sending new UPPs, but is still usable to verify old ones (...).
```
In general a invocation of the `pubkey-util.py` script will look like this:
```
$ python pubkey-util.py ENV OPERATION ...PARAMETERS...
```
Each operation has an own set of sub-parammeters. To see more information about a specific operation run:
```
$ python pubkey-util.py ENV OPERATION --help
```
To see a general help message run:
```
$ python pubkey-util.py --help
```

For some operations a date string in a specific format will be needed (a specific case of ISO8601); this command can be used to generate date strings in this format:
```
$ TZ=UTC date "+%Y-%m-%dT%H:%M:%S.000Z"
2022-02-23T11:11:11.000Z
```
### Registering ECDSA Keys
Currently the only way to register ECDSA Keys is by using X.509 certificates. This can be done by usign the `x509-registrator.py` script. It's able to generate an ECDSA keypair for a UUID + store it in a keystore, or read it from said keystore and generate a X.509 certificate for it. Additionally it will send the certificate the the uBirch backend to register they keypair.

**Warning**: Only ECDSA keys using the `NIST256p` curve and `Sha256` as hash function are supported! Others **won't** be accepted by the backend!

Below is a simple example call to register an ECDSA KeyPair to the backend. Note, that the keypair doesn't have to exist yet. If it doesn't it will be generated in the keystore (`devices.jks`). The first four arguments are positional. They are:

`<ENV> <KEYSTORE_FILE> <KEYSTORE_PASS> <UUID>`

`ENV` is the uBirch environment and must be one of `dev`, `demo` or `prod`. The `KEYSTORE_FILE` must be a pfad to a valid JavaKeyStore file (normal extension: `.jks`). `KEYSTORE_PASS` must be the password needed to unlock the given keystore. `UUID` is the uuid of the identity to work with.
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