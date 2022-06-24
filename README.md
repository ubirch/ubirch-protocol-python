[**Documentation and examples**](https://developer.ubirch.com/ubirch-protocol-python/)

[**Function Documentation**](https://developer.ubirch.com/function_documentation/ubirch-protocol-python/)

---

<!-- IMPORTANT
  The Getting Started and the README have the same content. 
  But for Github to render it as the repo description and Github Pages (Jekyll) to be able to find it, there need to be two.
  The links are different in some places, so please don't just copy paste everything while doing changes.
-->

<p align="center">
    <a href="#installation">Installation</a> •
    <a href="#setup">Setup</a> •
    <a href="#a-minimal-application">A minimal application</a>
</p>

The [ubirch-protocol](https://github.com/ubirch/ubirch-protocol) is a protocol to ensure the integrity (is unchanged) and identity (ownership) of data.

Ubirch handles data verification, and blockchain transactions to lock data points in time for proofable logs.

This is the implementation of the ubirch-protocol in **Python 3**.



## Installation
Optionally create environment to install to:

`$ python -m venv venv`

`$ . venv/bin/activate`

Install the requirements and Ubirch library using pip:

`$ pip install -r requirements.txt`

`$ pip install ubirch-protocol`

> Currently the library in pip is not the same as the library in `ubirch/` in this repository 

If want to install from another source than pip, follow along [here](docs/NotPip.md). 

## Setup
Before anything, you will need to do/get a couple of things:
- Open up the [uBirch Console](https://console.demo.ubirch.com) (`'demo'` stage)
  - For guidance, check out the [uBirch console documentation](https://developer.ubirch.com/console.html)
  - First register to get an account 
  - Then Create a "Thing":
    - Using a UUID generated with a [UUID-Generator](https://www.uuidgenerator.net/)
  - You will be using the shown UUID (ID) and the generated Auth-Token (password) from now on
- Come up or [generate](https://www.random.org/passwords/) a password for the KeyStore, which is where public and private Keys will be stored locally

> Open up the [Getting started](https://developer.ubirch.com/ubirch-protocol-python/GettingStarted.html) on the [Documentation and Examples](https://developer.ubirch.com/ubirch-protocol-python/) pages or continue below.

### Now you should have the following at hand:

Our [Ubirch API](http://developer.ubirch.com/function_documentation/ubirch-protocol-python/) 
authentication with an uuid and a password:
```python
from uuid import UUID

uuid = UUID(hex = "f5ded8a3-d462-41c4-a8dc-af3fd072a217")
auth            = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

And credentials for a [KeyStore](http://developer.ubirch.com/function_documentation/ubirch-protocol-python/) 
to store your public and private key:
```python
keystore_name     = "devices.jks"
keystore_password = "XXXXXXXXXXX"
```

## A minimal application
The smallest uBirch application looks something like this. 

*The code can be found in [`GettingStarted.py`](examples/GettingStarted.py) as well.*

Lets say we have got some weather-sensor data like:

```python
import time

data = {
    "timestamp": int(time.time()),
    "temperature": 11.2,
    "humidity": 35.8,
    "status": "OK"
}
```

To send a hash of the data to the Ubirch backend run these few lines inside of `examples/`:
```python
import ubirch
from UbirchWrapper import UbirchWrapper

client = UbirchClient(uuid, auth, keystore_name=keystore_name, keystore_password=keystore_password)
client.checkRegisterPubkey()

currentUPP = client.createUPP(data)

response = client.api.send(uuid, currentUPP)
client.handleMessageResponse(response)

client.verifyResponseSender(response)

previousSignatureInUPP = client.extractPreviousSignature(response)
client.assertSignatureCorrect(previousSignatureInUPP)

print("Successfully sent the UPP and verified the response!")

client.protocol.persist(uuid)
```

1. Initialize an UbirchClient instance and pass the credentials for a `KeyStore`
2. Check if the public key is registered at the Ubirch key service and register it if necessary
3. Create a chained Ubirch protocol packet (UPP) that contains a hash of the data 
4. Send the UPP to the Ubirch backend using the `API`
5. Handle the response
6. Verify that the response came from the backend
7. Unpack the received UPP to get its previous signature 
8. Make sure it is the same as the UPP signature sent
9. Persist signature: Save last signatures to a `.sig` file

*This example uses the example [UbirchWrapper](examples/UbirchWrapper.py) that helps to implement general repetitive tasks.*

> **Next:** Take a look at the Step-by-step-example on the [Documentation Pages](https://developer.ubirch.com/ubirch-protocol-python/)


## Testing
Unit tests are added to test the functionality of objects provided in this library.

```bash
pip install -r requirements.test.txt
python -m pytest tests
```

