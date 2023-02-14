[**Documentation and examples**](https://developer.ubirch.com/ubirch-protocol-python/)

[**Function Documentation**](https://developer.ubirch.com/function_documentation/ubirch-protocol-python/)

---

<!-- WHEN EDITING THIS FILE:
  The Getting Started and the README have the same content. 
  But for GitHub to render it as the repo description and GitHub Pages (Jekyll) to be able to find it, there need to be two.
  The links are different in some places, so please don't just copy and paste everything while doing changes.
-->

<p align="center">
    <a href="#installation">Installation</a> •
    <a href="#setup">Setup</a> •
    <a href="#a-minimal-application">A minimal application</a>
</p>

---

This repository contains a library providing an implementation of
the [Ubirch-protocol](https://github.com/ubirch/ubirch-protocol) in **Python 3**.

That, along with the helper classes `KeyStore` and `API`. These can be used to handle cryptographic keys and to
communicate with the Ubirch backend.

Additionally, you will find the raw documentation files rendered to
the [documentation pages](https://developer.ubirch.com/ubirch-protocol-python/).

## Installation
Optionally create environment to install to:

`$ python -m venv venv`

`$ . venv/bin/activate`

Install the requirements and ubirch library using pip:

`$ pip install -r requirements.txt`

`$ pip install ubirch-protocol`

> The required version of the `ubirch-protocol` package to run the provided scripts is `3.1.0`.
> Currently this version can only be installed through a [local install](NotPip.md). 


If you want to install from another source than pip, follow along [here](NotPip.md).

## Setup
Before anything, you will need to do/get a couple of things:
- Open up the [Ubirch Console](https://console.demo.ubirch.com) (`'demo'` stage)
  - For guidance, check out the [uBirch console documentation](https://developer.ubirch.com/console.html)
  - First register to get an account 
  - Then Create a "Thing":
    - Using a UUID generated with a [UUID-Generator](https://www.uuidgenerator.net/)
  - You will be using the shown UUID (ID) and the generated Auth-Token (password) from now on
- Come up or [generate](https://www.random.org/passwords/) a password (`KEYSTORE_PWD`) for the KeyStore (`KEYSTORE`), which is where public and private Keys will be stored locally

### Now you should have the following at hand:

Our [Ubirch API](http://developer.ubirch.com/function_documentation/ubirch-protocol-python/) 
authentication with a `UUID` and an `AUTH_TOKEN`. together with 
credentials `KEYSTORE` and `KEYSTORE_PWD` for a [KeyStore](http://developer.ubirch.com/function_documentation/ubirch-protocol-python/)

## A minimal application
The smallest uBirch application looks something like this. 

*The code can be found in [`examples/GettingStarted.py`](../examples/GettingStarted.py) as well.*

*Run it from your command prompt using `$ python3 GettingStarted.py <UUID> <AUTH_TOKEN> <KEYSTORE> <KEYSTORE_PWD>` or copy-paste the codeblocks.*

Let's say we have got some environment-sensor data like:

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
from UbirchWrapper import UbirchWrapper

# (1) Initialize an UbirchWrapper instance and pass the credentials for a `KeyStore`
client = UbirchWrapper(uuid, auth, keystore_name, keystore_password)

# (2) Check if the public key is registered at the Ubirch key service and register it if necessary
client.checkRegisterPubkey()

# (3) Create a chained Ubirch protocol packet (UPP) that contains a hash of the data 
currentUPP = client.createUPP(data)

# (4) Send the UPP to the Ubirch backend using the API and handle the response
response = client.api.send(uuid, currentUPP)
client.handleMessageResponse(response)

# (5) Verify that the response came from the backend
client.verifyResponseSender(response)

# (6) Unpack the received UPP to get its previous signature 
previousSignatureInUPP = client.extractPreviousSignature(response)

# (7) Make sure it is the same as the UPP signature sent
client.assertSignatureCorrect(previousSignatureInUPP)

# (9) Persist signature: Save last signatures to a `.sig` file
client.protocol.persist(uuid)

print("Successfully sent the UPP and verified the response!")
```

*This example uses the example [UbirchWrapper](../examples/UbirchWrapper.py) that helps to implement general repetitive tasks.*

> **Next:** Take a look at the Step-by-step-example on
> the [Documentation Pages](https://developer.ubirch.com/ubirch-protocol-python/)

## Testing

Unit tests are added to test the functionality of objects provided in this library.

```bash
pip install -r requirements.test.txt
python -m pytest tests
```

## Ubirch Internal Documentation

About the repository automation
refer [here](https://ubirch.atlassian.net/wiki/spaces/UBD/pages/2342092819/Template+repository+for+better+documentation)
.

- If the deployment fails make sure the Personal access token is up-to-date
