Welcome in the documentation of the [ubirch-protocol](https://github.com/ubirch/ubirch-protocol) in Python!

# Getting Started 

Take a look at the [Quickstart](Quickstart.md) or at the more detailed [Step by Step guide](StepByStep.md).

Afterwards consider the Article about a [UPP's Lifecycle](uppLifecycle.md)

---

# Components

The ubirch library consists of three parts which can be used individually:

**[API](../ubirch/ubirch_api.py)** - `ubirch.ubirch_api.API` 

- A python layer covering the ubirch backend REST API

**[Protocol](../ubirch/ubirch_protocol.py)** - `ubirch.ubirch_protocol.Protocol`

- The protocol compiler which packages messages and handles signing and verification

**[KeyStore](../ubirch/ubirch_ks.py)** - `ubirch.ubirch_ks.KeyStore`

- A simple key store based on [pyjks](https://pypi.org/project/pyjks/) to store keys and certificates

> The [ubirch](https://ubirch.com) protocol uses the [Ed25519](https://ed25519.cr.yp.to/) signature scheme by default. But [ECDSA](https://www.encryptionconsulting.com/education-center/what-is-ecdsa/) is implemented as well.

