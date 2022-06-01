
# function documentation

<!-- This markdown file is supposed to be read by doxygen, 
a software for generating documentation. So don't wonder about the @note statement. 
Please refer as well to the official documentation at 
developer.ubirch.com -->

[**Documentation and examples**](https://developer.ubirch.com/ubirch-protocol-python/)

[**Github repository**](https://github.com/ubirch/ubirch-protocol-python/tree/ecdsa-betterReadMe)

---

## Components
The ubirch library consists of three parts which can be used individually:

**[API](@ref ubirch.ubirch_api.API)** - `ubirch.ubirch_api.API` 

- A python layer covering the ubirch backend REST API

**[Protocol](@ref ubirch.ubirch_protocol.Protocol)** - `ubirch.ubirch_protocol.Protocol`

- The protocol compiler which packages messages and handles signing and verification

**[KeyStore](@ref ubirch.ubirch_ks.KeyStore)** - `ubirch.ubirch_ks.KeyStore`

- A simple key store based on [pyjks](https://pypi.org/project/pyjks/) to store keys and certificates

---

@note There is darkmode! You can find it next to the searchbar.
