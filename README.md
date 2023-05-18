[**Documentation and examples**](https://developer.ubirch.com/ubirch-protocol-python/)

[**Function Documentation**](https://developer.ubirch.com/function_documentation/ubirch-protocol-python/)

---

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


## Step By Step Example
Take a look at the Step-by-step-example on the [Documentation Pages](https://developer.ubirch.com/ubirch-protocol-python/).

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
