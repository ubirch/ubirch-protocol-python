# Example Client for IIoT

`example-client-iiot.py` is an example of a ubirch client which supports MQTT and OPC-UA to aggregate and seal data in an IIoT (industrial internet of things) setting.
Further protocols or hardware interfaces can be added by implementing callbacks for receiving, parsing, and queueing incoming data.

## Adding Protocols or Hardware Interfaces

To implement this, basically implement or import the desired protocol on python level first and make sure you can receive data properly. Then have your hardware/message callback or manually executed function call `queue_message(myMessageObject)` and add suitable parsing to `queue_message()`. The data will then be integrated into the next block of data from the queue.

## Installation on a Revolution Pi RevPi Core 3

* Follow the quick start guide for setting up the RevPi: https://revolution.kunbus.com/MANUAL/
* Make sure the system and all packages are on the latest versions by using the following commands: 
  * `sudo apt-get update`
  * `sudo apt-get upgrade`
  * `sudo apt-get dist-upgrade`

* Selectively upgrade python3, as we need python > 3.6 (This will become unecessary ass soon as Kunbus moves to buster release.):
  * `sudo nano /etc/apt/sources.list`
  * duplicate the line containing 'stretch' and replace 'stretch' with buster, save the file.
  * `sudo apt-get update`
  * `sudo apt-get install python3`
  * run `sudo nano /etc/apt/sources.list` and remove the line with 'buster' you added before
  * `sudo apt-get update`

* Clone this repository:
  * `mkdir iiot-test`
  * `cd iiot-test`
  * `git clone --single-branch --branch UNG-484-IIoT-examples https://github.com/ubirch/ubirch-protocol-python.git`

* Install the requirements from the 'examples' folder. (Not from the repository root folder!):
  * `pip3 install -r ~/iiot-test/ubirch-protocol-python/examples/requirements.txt`

* Change into the example directory, copy, and edit the config file (see [Configuration] for details of the settings):
  * `cd ubirch-protocol-python/examples/`
  * `mkdir ~/persist-ubirch-iiot-client/`
  * `cp iiot-client-config_example.json ~/persist-ubirch-iiot-client/iiot-client-config.json`
  * `cd ~/persist-ubirch-iiot-client/`
  * `sudo nano iiot-client-config.json` and adapt the file with your settings (see [Configuration])

* Run the client with the config:
  * `python3 ~/iiot-test/ubirch-protocol-python/examples/example-client-iiot.py ./iiot-client-config.json`

* If desired, add the python commandline to autostart mechanism of the system and redirect the output to logfiles of your choice.

## Configuration

To run the client, you will first need to make the ubirch backend aware of it.
First you need to generate a Universally Unique Identifier (UUID) for your device.
If you are on linux, you can use the `uuidgen` tool in the console.
Alternatively, you can generate a [version 4 UUID online](https://www.uuidgenerator.net/version4).
Copy that UUID somewhere for use later.

With this UUID generated, go to the [UBIRCH web UI](https://console.prod.ubirch.com):

(Note: if you want to use a stage different than `prod` replace `prod` with `demo` or `dev` in the URL.)
- Login or register if you don't have an account yet.
- Go to **Things** (in the menu on the left) and click on `+ ADD NEW DEVICE`.
- In the resulting form enter the following data:
    - Select ID type **UUID**
    - Enter the UUID you just generated in the **ID** field
    - Add a **description** for your device (e.g. "Test Device 1")
- Click on `register`.
- Click on your device in the *Your Things* overview and copy the content of the `password` value in the `apiConfig` field somewhere for use later.

The client itself is then configured via a json settings file which is passed to it as an argument.
You can copy the example file from this repository (`examples/iiot-client-config_example.json`) as a starting point.
An example for this file is given here:
```
{
    "api_device_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "api_password":  "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy",
    "api_enviroment": "prod",
    
    "persistent_storage_location" : "~/persist-ubirch-iiot-client/",
    "keystore_password": "yoursecretkeystorepassword",
    "aggregate_interval": 10,
    "seal_interval": 10,

    "opcua_enabled": true,
    "opcua_address": "opc.tcp://username:password@192.168.1.81:4840/",
    "opcua_namespace": "urn:wago-com:codesys-provider",
    "opcua_nodes": [ "|var|RSConnect.Application.GVL_OPCUA.Input1",
        "|var|RSConnect.Application.GVL_OPCUA.Input2",
        "|var|RSConnect.Application.GVL_OPCUA.output1_visu",
        "|var|RSConnect.Application.GVL_OPCUA.counter_input",
        "|var|RSConnect.Application.GVL_OPCUA.counter_output",
        "|var|RSConnect.Application.GVL_OPCUA.temperature1"],

    "mqtt_enabled": true,
    "mqtt_address": "192.168.1.81",
    "mqtt_port": 1883,
    "mqtt_topics": ["/ubirch/rsconnectdata/temperature"],
    "mqtt_client_id": "ubirch-client-123",
    "mqtt_username": "myuser",
    "mqtt_password": "mypassword"
}
```

Fill in the device ID/UUID and the api password from earlier, and check that you have set the correct api enviroment.
For this, following parameters are available:
- `api_device_id`: ID/UUID shown under 'Things' in the UBIRCH Web UI.
- `api_password`: Password value from the `apiConfig` field for this device shown in the UBIRCH Web UI under *Your Things*.
- `api_enviroment`: Stage to use. Can be `prod`, `demo` or `dev`. Must match stage where the device was registered.
    
Then, setup the storage and aggregating/sealing parameters:
- `persistent_storage_location`: Where the client can save persistent data such as keys, received data, data ready to be sent, etc. Also this is the location where the mock customer backend will write data which was "received".
- `keystore_password`: Password for encrypting the keys on disk. If left empty or not defined, password is prompted on startup of the client.
- `aggregate_interval`: How often to aggregate IIoT data into blocks for sealing. (Seconds)
- `seal_interval`: How often to seal aggregated data blocks and anchor them at the ubirch backend. (Seconds)

Then, configure your OPC UA settings:

- `opcua_enabled`: Enable or disable OPC UA. Can be true/false.
- `opcua_address`: Address and port of the OPC UA server, can contain username/password e.g. `opc.tcp://username:password@192.168.1.81:4840/`. If not needed, just romve it e.g. `opc.tcp://192.168.1.81:4840/`
- `opcua_namespace`: The namespace where the nodes to subscribe to are located.
- `opcua_nodes`: List of nodes to subscribe to.

Finally, setup MQTT:

- `mqtt_enabled`: Enable or disable MQTT. Can be true/false.
- `mqtt_address`: Address of MQTT broker.
- `mqtt_port`: Port of MQTT broker.
- `mqtt_topics`: List of topics to subscribe to.
- `mqtt_client_id`: Client ID to send to broker. Set to `""` to auto-generate. Must be unqiue on broker side.
- `mqtt_username`: Username for authentication at server. Can be omitted or `null`.
- `mqtt_password`: Password for authentication at server. Can be omitted or `null`.

Save the file and start the client with it, e.g.: `python3 example-client-iiot.py ~/persist-ubirch-iiot-client/client_config_prod.json`.