# Readme for data-UPPs and ubirch API calls via JWT

A Data-UPP is a UPP, where the `payload` field is not a `hash`, like in a standard UPP, but is replaced by the `data` itself, after the signing process. To mark the data-UPP, the `type` field is also set to `0x70`. For more details, please refer to [Concept Paper Data-UPP](./Concept%20Paper%20Data-UPP.pdf).

>**Note**: The data-UPP cannot be anchored as such, because it was modified after the signature. To verify a data-UPP, the hash of the data has to be calculated and replaced in the `payload` field, also the `type` field has to be replaced. 

>**Note**: For the ubirch API calls, it is required, that the device-UUID as well as the public key of the device have to be registered at ubirch. The UUID can be registered on [console.prod.ubirch.com](https://console.prod.ubirch.com). For the public-key, please refer to [DevTools.md](../../docs/DevTools.md), where the key registratation is explained and demonstrated.

## Create a data-UPP

To create a data-UPP, the [data-upp-creator.py](./data_upp_creator.py) script can be used. The script generates a standard UPP and signs it. Afterwards, the fields `payload` and `type` are replaced and the data-UPP is created. After executing the script, a data-UPP will be stored into the file, given by the output parameter.

The usage of this script can be aquired with:
```bash
$ python3 data-upp-creator.py -h
```

An example usage with an already registered device with UUID: `98880181-4770-44da-85a9-da86a6ccaa1f`  is:
```bash
$ python3 data_upp_creator.py --version 0x23 --isjson true --output upp.bin --hash sha256 -k my-keystore.jks -p password 98880181-4770-44da-85a9-da86a6ccaa1f '{"timestamp": 1625163338, "temperature": 11.2, "humidity": 35.8, "status": "OK", "something": "different", "new": "value" }'

2023-10-17 17:04:15,453                 root        init_keystore() INFO     Public/Verifying key for UUID: "98880181-4770-44da-85a9-da86a6ccaa1f" algortihm is:"ECDSA", is [hex]: "fb5be8d6e2c65165dd4b77def906700a4da4dfd67c488577c783ca0bdef5d346123f4f22f506ba232ddffb04ee29d2033647d6588b8782efb6da91bd607e32ed" and [base64]: "+1vo1uLGUWXdS3fe+QZwCk2k39Z8SIV3x4PKC97100YSP08i9Qa6Iy3f+wTuKdIDNkfWWIuHgu+22pG9YH4y7Q=="
2023-10-17 17:04:15,453                 root                 load() DEBUG    loaded 1 known signatures
2023-10-17 17:04:15,453                 root      prepare_payload() INFO     Serialized data JSON: "{"humidity":35.8,"new":"value","something":"different","status":"OK","temperature":11.2,"timestamp":1625163338}"
2023-10-17 17:04:15,453                 root      prepare_payload() INFO     UPP payload (sha256 hash of the data) [base64]: "c5kAs3Wani1ltmHNRUZ477P9zOYRgsD3MD7t8BsDMC8="
2023-10-17 17:04:15,454                 root           create_upp() INFO     Generating a chained signed UPP for UUID "98880181-4770-44da-85a9-da86a6ccaa1f"
2023-10-17 17:04:15,459                 root           create_upp() INFO     packed UPP [hex]: "9623c41098880181477044da85a9da86a6ccaa1fc440d7dd65be1394c7353104e05ae5a4cda5fb4cb42f40055b95ca1f55cb19f8a42cd2b28ff6ade917b73ce7ef5fde14bf0941c4c532a39bcb9d0296dfcd71cbdf0200c420739900b3759a9e2d65b661cd454678efb3fdcce61182c0f7303eedf01b03302fc440a20f8f358f7be7b1d5abec8b9ab631d2a77dae135e5b3abd6494a45c359dd163df5a9c1e1e681af7c45144fead4585c376ce2e6f3b0d6ccf25113b918af85855"
2023-10-17 17:04:15,459                 root  show_store_data_upp() INFO     data-UPP [hex]: "9623c41098880181477044da85a9da86a6ccaa1fc440d7dd65be1394c7353104e05ae5a4cda5fb4cb42f40055b95ca1f55cb19f8a42cd2b28ff6ade917b73ce7ef5fde14bf0941c4c532a39bcb9d0296dfcd71cbdf0270c46f7b2268756d6964697479223a33352e382c226e6577223a2276616c7565222c22736f6d657468696e67223a22646966666572656e74222c22737461747573223a224f4b222c2274656d7065726174757265223a31312e322c2274696d657374616d70223a313632353136333333387dc440a20f8f358f7be7b1d5abec8b9ab631d2a77dae135e5b3abd6494a45c359dd163df5a9c1e1e681af7c45144fead4585c376ce2e6f3b0d6ccf25113b918af85855"
2023-10-17 17:04:15,459                 root  show_store_data_upp() INFO     data-UPP written to "upp.bin"
```
The log output shows the `packed UPP`, which is a standard UPP and also the `data-UPP`, which at the end of the script is stored in `upp.bin` in binary form.  

## Verify a data-UPP locally

To verify the data-UPP, the above mentioned modifications on the UPP (`payload` and `type`) have to be modified again, to create a standard-UPP, which then can be verified locally. This can be done with the script [data_upp_verifier.py](./data_upp_verifier.py). To use the script, the public key for the specific UUID of the device, which created the data-UPP needs to be known or aquired. To request the public-key of a UUID, please refer to the [API_get_public_key.sh](./API_get_public_key.sh) script. 

The usage of this script can be aquired with:
```bash
$ pytohn3 data_upp_verifier.py -h
```

An example usage with an already registered device with UUID: `98880181-4770-44da-85a9-da86a6ccaa1f`  is:
```bash
$ python3 data_upp_verifier.py --hash sha256 --isecd true -k fb5be8d6e2c65165dd4b77def906700a4da4dfd67c488577c783ca0bdef5d346123f4f22f506ba232ddffb04ee29d2033647d6588b8782efb6da91bd607e32ed -u 98880181-4770-44da-85a9-da86a6ccaa1f -i upp.bin

2023-10-17 17:04:44,288                 root        read_data_upp() INFO     Reading the input data-UPP from "upp.bin"
2023-10-17 17:04:44,288                 root      unpack_data_upp() INFO     Unpacked UPP: "[35, b'\x98\x88\x01\x81GpD\xda\x85\xa9\xda\x86\xa6\xcc\xaa\x1f', b'\xd7\xdde\xbe\x13\x94\xc751\x04\xe0Z\xe5\xa4\xcd\xa5\xfbL\xb4/@\x05[\x95\xca\x1fU\xcb\x19\xf8\xa4,\xd2\xb2\x8f\xf6\xad\xe9\x17\xb7<\xe7\xef_\xde\x14\xbf\tA\xc4\xc52\xa3\x9b\xcb\x9d\x02\x96\xdf\xcdq\xcb\xdf\x02', 112, b'{"humidity":35.8,"new":"value","something":"different","status":"OK","temperature":11.2,"timestamp":1625163338}', b'\xa2\x0f\x8f5\x8f{\xe7\xb1\xd5\xab\xec\x8b\x9a\xb61\xd2\xa7}\xae\x13^[:\xbdd\x94\xa4\\5\x9d\xd1c\xdfZ\x9c\x1e\x1eh\x1a\xf7\xc4QD\xfe\xadE\x85\xc3v\xce.o;\rl\xcf%\x11;\x91\x8a\xf8XU']"
2023-10-17 17:04:44,288     ubirch.ubirch_ks           _load_keys() WARNING  creating new key store: -- temporary --
2023-10-17 17:04:44,288                 root         check_cli_vk() INFO     Loading the key as ECDSA NIST256p SHA256 verifying key
2023-10-17 17:04:44,288                 root         check_cli_vk() INFO     Inserted "98880181-4770-44da-85a9-da86a6ccaa1f": "fb5be8d6e2c65165dd4b77def906700a4da4dfd67c488577c783ca0bdef5d346123f4f22f506ba232ddffb04ee29d2033647d6588b8782efb6da91bd607e32ed" (UUID/VK) into the keystore
2023-10-17 17:04:44,288                 root         get_upp_uuid() INFO     UUID of the UPP creator: "98880181-4770-44da-85a9-da86a6ccaa1f"
2023-10-17 17:04:44,288                 root             pack_upp() INFO     Serialized data JSON: "{"humidity":35.8,"new":"value","something":"different","status":"OK","temperature":11.2,"timestamp":1625163338}"
2023-10-17 17:04:44,288                 root             pack_upp() INFO     UPP payload (sha256 hash of the data) [base64]: "c5kAs3Wani1ltmHNRUZ477P9zOYRgsD3MD7t8BsDMC8="
2023-10-17 17:04:44,288                 root             pack_upp() INFO     repacked UPP [hex]: "9623c41098880181477044da85a9da86a6ccaa1fc440d7dd65be1394c7353104e05ae5a4cda5fb4cb42f40055b95ca1f55cb19f8a42cd2b28ff6ade917b73ce7ef5fde14bf0941c4c532a39bcb9d0296dfcd71cbdf0200c420739900b3759a9e2d65b661cd454678efb3fdcce61182c0f7303eedf01b03302fc440a20f8f358f7be7b1d5abec8b9ab631d2a77dae135e5b3abd6494a45c359dd163df5a9c1e1e681af7c45144fead4585c376ce2e6f3b0d6ccf25113b918af85855"
2023-10-17 17:04:44,295                 root           verify_upp() INFO     Signature verified - the UPP is valid!
2023-10-17 17:04:44,295                 root            store_upp() INFO     UPP written to "standard_upp.bin"
```
The logs of this script show the `Unpacked UPP`, the `Serialized data JSON` and also the `repacked UPP` together with the verification result. In the end the verified UPP is stored in the given `--output` parameter, in this case "standard_upp.bin" in binary form.

## API calls

Once the UPP is created, it can be anchored via [API_test_anchoring_jwt.sh](./API_test_anchoring_jwt.sh) and afterwards verified via [API_test_verifying_jwt.sh](./API_test_verifying_jwt). 
> **Note:** Please check the scripts, before using them, for the parameters and data.





