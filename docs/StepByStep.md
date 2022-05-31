
# Step by step instructions

*The code can be found in one place in `StepByStepExample.py` as well.*

Make sure to follow the setup steps in [Quickstart](Quickstart.md) first.

## Additional setup steps

### About the stage
Choose a stage to work on
- Get an account for the uBirch-Console
  - https://console.prod.ubirch.com for the `prod` stage
  - https://console.demo.ubirch.com for the `demo` stage
  - https://console.dev.ubirch.com for the `dev` stage


### About the Keystore
### Generating and managing a keypair
To create, or more precisely, to _sign_ a UPP, a device will need a keypair. 
This keypair consist of a private key (_signing key_) and public key (_verifying key_). 

The signing key is used to sign UPPs and the verifying key can be used by the uBirch backend to check, if the signature is valid and belongs to the correct sender/signer. 
So, logically it doesn't matter who knows the verifying key, but the signing key must be kept secret all the time. 
In a real use case a device might store it in a TPM ([Trusted platform module](https://en.wikipedia.org/wiki/Trusted_Platform_Module)) or use other counter measures against attackers reading the key from the device. 

For this demo, keypairs will be stored in a [JKS Keystore](https://en.wikipedia.org/wiki/Java_KeyStore) using the [`pyjks`](https://pypi.org/project/pyjks/) library. 
Therefore, you will have to choose and remember a file path for that keystore and a password used to encrypt it. 
The process of actually generating the keypair is handled by the script.

TODO: Explain Keystore (Password) security

