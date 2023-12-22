# Changelog

## v3.3
- support for ECDSA cryptographic algorithm
- extended tests for ECDSA algorithm
- extended tool scripts in [tools](./tools/)
    - updated documentation for tools in [DevTools](./docs/DevTools.md)
- added doxygen documentation generation 
- added automated deployment of documetation pages
- reduced [examples](./examples/) to minimum of
    - [StepByStepExample.py](./examples/StepByStepExample.py)
    - [test-identity.py](./examples/test-identity.py)
    - [test-protocol.py](./examples/test-protocol.py)
- added requirements for tools and examples
- added [ubirch_backend_keys.py](./ubirch/ubirch_backend_keys.py) for simplified access to backend UUIDs and public keys
- in [ubirch_protocol.py](./ubirch/ubirch_protocol.py) 
    - the method `message_verify()` has been replaced by `verify_signature()`
    - the method `_sign()` and `_verify()` need to take care of the hashing before signing, if this is required by the used algorithm
