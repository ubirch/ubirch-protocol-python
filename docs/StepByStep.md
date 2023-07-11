# Step By Step Example

1. [Basic functionality](#basic-functionality)
2. [Programmatic flow](#programmatic-flow)

## Basic functionality

This example is build for single device usage with a specified UUID. It can handle two different cryptographic algorithms, [Ed25519](https://en.wikipedia.org/wiki/EdDSA#Ed25519) and [ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm). 

The private public key pairs are stored in a keystore and can be selected via the specific UUID for the device. 
> Note: for each UUID, only one set of keys can be stored. Since the key handling is always via the keystore, the backend public keys are stored there at the initialization process. Depending on the cryptographic algorithm, the unused backend keys are replaced, see [here](../examples/StepByStepExample.py#L34-L38) and [here](../examples/StepByStepExample.py#L50-L54).


*The code can be found in [`StepByStepExample.py`](../examples/StepByStepExample.py).*

**Run it from your command prompt using** 
```
$ python StepByStepExample.py <Keystore Path> <Keystore Password> <UUID> <Authentication Token> [uBirch Environment] [Crypto Algorithm]
```
with the parameters
- `Keystore Path` -> Path to the Keystore. If it doesn't exist yet, it will be created.
- `Keystore Password` -> Password for the Keystore.
- `UUID` -> UUID of the device, i.e. `01234567-1234-2345-3456-0123456789abc`
- `Authentication Token` -> Authentication token to be used for the uBirch backend.
- `uBirch Environment` -> *(Optional)* The uBirch Environment to be used, see [here](../examples/StepByStepExample.py#L10).
   - `dev` -> Ubirch internal development stage (not reliable)
   - `demo` -> *(default)* demonstration stage (for testing only)
   - `prod` -> production stage 
- `Crypto Algorithm` -> *(Optional)* The crypto algorithm to be used., see [here](../examples/StepByStepExample.py#L9)
   - `ed25519` -> *(default)* the [Ed25519](https://en.wikipedia.org/wiki/EdDSA#Ed25519) Algorithm
   - `ecdsa` -> the [ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm) Algorithm

## Programmatic flow

This `StepByStepExample` is a simple One-shot example of the ubirch functionality without a loop. 

The [data](../examples/StepByStepExample.py#L190-L195) in this case is represented by a JSON object and can be replaced by custom data. 

>Note: the data must always be unique in order to generate unique hash values. If the data is not unique, the backend will respond with the status code `409`, because then the hash was already anchored before.

If repitition is required, a loop can be setup around [here](../examples/StepByStepExample.py#L188-L251). 

The individual steps of the example are described and linked below.

- [load previous signature](../examples/StepByStepExample.py#L24)
- load or generate key and set the hashing algorithm [ecdsa](../examples/StepByStepExample.py#L27-L41) or [ed25519](../examples/StepByStepExample.py#L43-L57)
    - [for new device register key](../examples/StepByStepExample.py#L173-L187)
- [generate Data](../examples/StepByStepExample.py#L190-L195)
- [create chained UPP](../examples/StepByStepExample.py#L199-L209)
    - [sign UPP](../examples/StepByStepExample.py#L208)
- [transmit UPP](../examples/StepByStepExample.py#L212)
    - [receive respone UPP](../examples/StepByStepExample.py#L212-L220)
        - [verify response UPP](../examples/StepByStepExample.py#L224-L230)
        - [verify signature chain](../examples/StepByStepExample.py#L234-L244)
- [store previous signature](../examples/StepByStepExample.py#L247)
