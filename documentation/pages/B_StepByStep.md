@page stepByStep Step by step instructions
@tableofcontents

<!-- These markdown files are supposed to be read only by doxygen. 
So don't wonder about the @ref - or similar statements
Please refer to the official documentation -->

Make sure to follow the setup steps in [Quickstart](@ref quickstart) first.


### Example uBirch client
[`example-client.py`](example-client.py) implements a full example uBirch client. It generates a keypair if needed, registers it at the uBirch backend if it doesn't know it yet, creates and sends a UPP and handles/verfies the response from the uBirch backend. The used message format looks like this:
```
{
  "id": "UUID",
  "ts": TIMESTAMP,
  "data": "DATA"
}
```
It has two positional and one optional command line parameters.
```
usage: python3 example-client.py <UUID> <ubirch-auth-token> [ubirch-env]
```
- `UUID` is the UUID as hex-string like `f5ded8a3-d462-41c4-a8dc-af3fd072a217`
- `ubirch-auth-token` is the uBirch authentication token for the specified UUID, e.g.: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
- `ubirch-env` (optional) specifies the environment/stage to operator on. `dev`, `demo` or `prod` (default).
Keys are loaded from/stored to `demo-device.jks`. The keystore-password can be read from the [script](example-client.py) itself.
