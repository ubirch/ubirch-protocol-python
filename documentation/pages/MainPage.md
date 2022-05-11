<!--
These markdown files are supposed to be read only by doxygen. 
So don't wonder about the @ref - or similar statements
Please refer to the official documentation
-->

@tableofcontents

Welcome in the documentation of the [ubirch-protocol](https://github.com/ubirch/ubirch-protocol) in [Python](https://www.python.org/)!

> The [ubirch](https://ubirch.com) protocol uses the [Ed25519](https://ed25519.cr.yp.to/) signature scheme by default. But [ECDSA](https://www.encryptionconsulting.com/education-center/what-is-ecdsa/) is implemented as well

## Components
The ubirch library consists of three parts which can be used individually:

**[API](@ref ubirch.ubirch_api.API)** - `ubirch.ubirch_api.API` 

- A python layer covering the ubirch backend REST API

**[Protocol](@ref ubirch.ubirch_protocol.Protocol)** - `ubirch.ubirch_protocol.Protocol`

- The protocol compiler which packages messages and handles signing and verification

**[KeyStore](@ref ubirch.ubirch_ks.KeyStore)** - `ubirch.ubirch_ks.KeyStore`

- A simple key store based on [pyjks](https://pypi.org/project/pyjks/) to store keys and certificates

## Getting Started

Take a look at the [Quickstart](@ref quickstart) 

@note The sidebar of this documentation sadly won't work well in Firefox 