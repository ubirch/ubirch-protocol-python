import binascii
import json
import logging
import sys
import time
import ed25519
from paho.mqtt import client as MqttClient
from uuid import UUID
from collections import deque
import base64

import ubirch

logging.basicConfig(format='%(asctime)s %(name)20.20s %(levelname)-8.8s %(message)s', level=logging.INFO)
logger = logging.getLogger()


########################################################################
# uirch protocol section
class VerifyProto(ubirch.Protocol):
    """
    Implements the ubirch-protocol for verifying only.
    """

    # public keys and UUIDs of the ubirch backend for verification of responses
    UUID_DEV = UUID(hex="9d3c78ff-22f3-4441-a5d1-85c636d486ff")
    PUB_DEV = ed25519.VerifyingKey("a2403b92bc9add365b3cd12ff120d020647f84ea6983f98bc4c87e0f4be8cd66", encoding='hex')
    UUID_DEMO = UUID(hex="07104235-1892-4020-9042-00003c94b60b")
    PUB_DEMO = ed25519.VerifyingKey("39ff77632b034d0eba6d219c2ff192e9f24916c9a02672acb49fd05118aad251", encoding='hex')
    UUID_PROD = UUID(hex="10b2e1a4-56b3-4fff-9ada-cc8c20f93016")
    PUB_PROD = ed25519.VerifyingKey("ef8048ad06c0285af0177009381830c46cec025d01d86085e75a4f0041c2e690", encoding='hex')

    def __init__(self, key_store: ubirch.KeyStore, uuid: UUID, device_pubkey: ed25519.VerifyingKey) -> None:
        super().__init__()
        self.__ks = key_store

        # insert device pubkey
        if not self.__ks.exists_verifying_key(uuid):
            self.__ks.insert_ed25519_verifying_key(uuid, device_pubkey)

        # check if the keystore already has the backend key for verification or insert verifying key
        if not self.__ks.exists_verifying_key(self.UUID_DEV):
            self.__ks.insert_ed25519_verifying_key(self.UUID_DEV, self.PUB_DEV)
        if not self.__ks.exists_verifying_key(self.UUID_DEMO):
            self.__ks.insert_ed25519_verifying_key(self.UUID_DEMO, self.PUB_DEMO)
        if not self.__ks.exists_verifying_key(self.UUID_PROD):
            self.__ks.insert_ed25519_verifying_key(self.UUID_PROD, self.PUB_PROD)

    def _sign(self, uuid: UUID, message: bytes) -> bytes:
        raise NotImplementedError

    def _verify(self, uuid: UUID, message: bytes, signature: bytes):
        return self.__ks.find_verifying_key(uuid).verify(signature, message)

########################################################################

########################################################################
# MQTT section
# MQTT funtions partly based on https://www.emqx.io/blog/how-to-use-mqtt-in-python
def mqtt_connect(address:str, port:int, client_id:str, enable_tls:bool, client_type:str, username: str = None, password:str = None) -> MqttClient:
    """
    Connect to an MQTT broker using the address, port and client ID. Can be either "receiver" type or "sender" type.
    For receiving type, the client will call mqtt_subscribe() in connect. Client ID must be unique on broker side.
    If username is set, username and password parameter are used for authenticating by passing them to paho mqtt username_pw_set().
    If enable_tls is true, paho mqtt set_tls() is called before starting the connection.
    Returns the client instance.
    """
    if client_type != "receiver" and client_type !="sender":
        logger.error(f"invalid MQTT client type: {client_type}, must be receiver or sender")
        sys.exit(1)

    def on_connect(client, userdata, flags, rc):
        if rc == 0:
            logger.info(f"MQTT-{client_type}: successfully connected to broker")
            if client_type == "receiver":
                mqtt_subscribe(client, MQTT_RECEIVE_TOPICS) # TODO: find a better way of resubscribing without using global topics variable
        else:
            logger.error(f"MQTT-{client_type}: failed to connect to broker, return code {rc} ({MqttClient.error_string(rc)})")

    def on_disconnect(client, userdata, rc):
        if rc !=0:
            logger.error(f"MQTT-{client_type}: unexpected disconnect")

    # Set Connecting Client ID
    client = MqttClient.Client(client_id)
    if username is not None:
        client.username_pw_set(username, password)
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.reconnect_delay_set(min_delay=1, max_delay=10)

    tls_state_string = "TLS disabled"
    if enable_tls:
        tls_state_string = "TLS enabled"
        client.tls_set()

    logger.info(f"MQTT-{client_type}: connecting to {address+' port '+str(port)+', '+tls_state_string}")
    client.connect(address, port)
    client.loop_start() # make mqtt client start processing traffic on its own in seperate thread
    return client

def mqtt_subscribe(client: MqttClient, topics: list):
    """Subscribe to all topics from the topics list using the given client."""
    def on_message(client, userdata, msg: MqttClient.MQTTMessage):
        global datablock_deque

        # handle payload string
        try:
            payload_string = msg.payload.decode('utf-8')
        except UnicodeDecodeError:
            logger.error(f"undecodable message payload on topic {msg.topic}: {binascii.b2a_hex(msg.payload)}") 
            return
        logger.info(f"MQTT-receiver: received message from topic {msg.topic}")
        logger.debug("MQTT-receiver: payload: {payload_string}")
        datablock_deque.appendleft(payload_string) # append left so the processing is FIFO (left in, right out)
    
    for topic in topics:
        logger.info("MQTT-receiver: subscribing to topic {}".format(topic))
        client.subscribe(topic,qos=1) #set QOS depending on your network/needed reliability
    client.on_message = on_message
########################################################################

def process_datablocks():
    """"
    Process all datablocks currently held in the queue
    """
    global datablock_deque

    while len(datablock_deque) > 0:
        payload_string = str(datablock_deque.pop())
        payload_elements = payload_string.split(" ",1)
        if len(payload_elements) != 2:
            logger.error(f"unable to split payload into UPP and datablock, discarding payload: {payload_string}")
            continue
        try:
            upp = base64.b64decode(payload_elements[0], validate=True)
        except Exception as e:
            logger.error(f"unable to decode UPP, discarding payload: {payload_string}")
            continue
        datablock = payload_elements[1]
        logger.info("Processing datablock with:")
        logger.info(f"UPP: {upp}")
        logger.info(f"data: {datablock}")
        #TODO: verify, process data, put back in case of temporary error (i.e. no connection)



#### start of main code section ###

# non-persistent queues for keeping received datablocks and UPPs in
datablock_deque = deque() # double ended queue

if len(sys.argv) < 2:
    print("example usage:")
    print(f"  python3 {sys.argv[0]} iiot-actuator-config.json")
    print("  See iiot-actuator-config_example.json for an example config.")
    sys.exit(0)

logger.info("actuator example started")

# configuration loading and general setup
logger.info("loading config")
with open(sys.argv[1], 'r') as f:
    config = json.load(f)

ENVIRONMENT = config['api_environment']

NANOCLIENT_UUID = UUID(hex=config['nanoclient_uuid'])
NANOCLIENT_PUBKEY = ed25519.VerifyingKey(config['nanoclient_pubkey'], encoding='hex')


logger.info(f'using endpoints at {ENVIRONMENT}.ubirch.com')
logger.info(f'nanoclient UUID is {NANOCLIENT_UUID}')
logger.info(f'nanoclient public key is {NANOCLIENT_PUBKEY}')

# MQTT setup for receiving datablocks+UPPs via MQTT
MQTT_RECEIVE_ADDRESS = config["mqtt_receive_address"]
MQTT_RECEIVE_PORT = config["mqtt_receive_port"]
MQTT_RECEIVE_TOPICS = config["mqtt_receive_topics"]
MQTT_RECEIVE_CLIENT_ID = config.get("mqtt_receive_client_id", "")
MQTT_RECEIVE_USERNAME = config.get("mqtt_receive_username", None)
MQTT_RECEIVE_PASSWORD = config.get("mqtt_receive_password", None)
MQTT_RECEIVE_TLS_ENABLED = config.get("mqtt_receive_tls_enabled", False)

connected_ok = False
while not connected_ok:
    try:
        mqtt_client_receiving = mqtt_connect(MQTT_RECEIVE_ADDRESS,MQTT_RECEIVE_PORT,MQTT_RECEIVE_CLIENT_ID, MQTT_RECEIVE_TLS_ENABLED, "receiver", MQTT_RECEIVE_USERNAME,MQTT_RECEIVE_PASSWORD)
        # (subscribing is handled in on_connect callback)
        connected_ok = True
    except Exception as e:
        logger.error(f"could not connect/subscribe to MQTT: {repr(e)}")
        cooldown = 10
        logger.info(f"retrying connection in {cooldown} seconds...")
        time.sleep(cooldown)

u_api = ubirch.API(env=ENVIRONMENT)
print(f"Doing check on {ENVIRONMENT} stage")
u_keystore = ubirch.KeyStore("temporary_keystore.jks", "notsecret")
u_protocol = VerifyProto(u_keystore, NANOCLIENT_UUID, NANOCLIENT_PUBKEY)

logger.info("starting main loop")
last_check = 0
try:
    while True:
        if len(datablock_deque) > 0:
            logger.info(f"attempting to process {len(datablock_deque)} datablocks")
            process_datablocks()

        time.sleep(0.0001)
except KeyboardInterrupt:
    pass
finally:
    logger.info("shutting down")
    if mqtt_client_receiving is not None:
        mqtt_client_receiving.disconnect()    
