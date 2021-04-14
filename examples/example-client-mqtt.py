import binascii
import hashlib
import json
import logging
import pickle
import random
import sys
import time
import queue #TODO: add to the requirements
from paho.mqtt import client as mqtt_client #TODO: add mqtt to the requirements file (?)
from uuid import UUID

from ed25519 import VerifyingKey
from requests import codes

import ubirch
from ubirch.ubirch_protocol import UBIRCH_PROTOCOL_TYPE_REG, UBIRCH_PROTOCOL_TYPE_BIN

logging.basicConfig(format='%(asctime)s %(name)20.20s %(levelname)-8.8s %(message)s', level=logging.DEBUG)
logger = logging.getLogger()


########################################################################
# Implement the ubirch-protocol with signing and saving the signatures
class Proto(ubirch.Protocol):
    UUID_DEV = UUID(hex="9d3c78ff-22f3-4441-a5d1-85c636d486ff")
    PUB_DEV = VerifyingKey("a2403b92bc9add365b3cd12ff120d020647f84ea6983f98bc4c87e0f4be8cd66", encoding='hex')
    UUID_DEMO = UUID(hex="07104235-1892-4020-9042-00003c94b60b")
    PUB_DEMO = VerifyingKey("39ff77632b034d0eba6d219c2ff192e9f24916c9a02672acb49fd05118aad251", encoding='hex')
    UUID_PROD = UUID(hex="10b2e1a4-56b3-4fff-9ada-cc8c20f93016")
    PUB_PROD = VerifyingKey("ef8048ad06c0285af0177009381830c46cec025d01d86085e75a4f0041c2e690", encoding='hex')

    def __init__(self, key_store: ubirch.KeyStore, uuid: UUID) -> None:
        super().__init__()
        self.__ks = key_store

        # check if the device already has keys or generate a new pair
        if not keystore.exists_signing_key(uuid):
            keystore.create_ed25519_keypair(uuid)

        # check if the keystore already has the backend key for verification or insert verifying key
        if not self.__ks.exists_verifying_key(self.UUID_DEV):
            self.__ks.insert_ed25519_verifying_key(self.UUID_DEV, self.PUB_DEV)
        if not self.__ks.exists_verifying_key(self.UUID_DEMO):
            self.__ks.insert_ed25519_verifying_key(self.UUID_DEMO, self.PUB_DEMO)
        if not self.__ks.exists_verifying_key(self.UUID_PROD):
            self.__ks.insert_ed25519_verifying_key(self.UUID_PROD, self.PUB_PROD)

        # load last signature for device
        self.load(uuid)

        logger.info("ubirch-protocol: device id: {}".format(uuid))

    def persist(self, uuid: UUID):
        signatures = self.get_saved_signatures()
        with open(uuid.hex + ".sig", "wb") as f:
            pickle.dump(signatures, f)

    def load(self, uuid: UUID):
        try:
            with open(uuid.hex + ".sig", "rb") as f:
                signatures = pickle.load(f)
                logger.info("loaded {} known signatures".format(len(signatures)))
                self.set_saved_signatures(signatures)
        except FileNotFoundError:
            logger.warning("no existing saved signatures")
            pass

    def _sign(self, uuid: UUID, message: bytes) -> bytes:
        return self.__ks.find_signing_key(uuid).sign(message)

    def _verify(self, uuid: UUID, message: bytes, signature: bytes):
        return self.__ks.find_verifying_key(uuid).verify(signature, message)


########################################################################

########################################################################
# Functions for managing MQTT data
# MQTT funtions partly based on https://www.emqx.io/blog/how-to-use-mqtt-in-python
mqtt_msg_queue = queue.Queue()
broker = '192.168.1.81'
port = 1883
topic = "/ubirch/rsconnectdata/temperature"
client_id = f'ubirch-mqtt-client-example'
def get_dataset():
    if mqtt_msg_queue.empty():
        return None

    # get messages received so far from queue and assemble info into dict
    messages_list = []
    while not mqtt_msg_queue.empty():
        message_item = mqtt_msg_queue.get()
        message_ts = message_item["msg_ts_ms"]
        message_obj = message_item["msg"]
        message_dict = {
            "msg_ts_ms": message_ts,
            "msg_topic": message_obj.topic,
            "msg_payload": message_obj.payload.decode("utf-8"), #TODO: this assumes that the payload is always UTF-8 string, add check/handling or different encoding
            "msg_qos": message_obj.qos,
            "msg_retain": message_obj.retain,
            "msg_mid": message_obj.mid
        }
        messages_list.append(message_dict)

    # assemble dataset by joining extra info and message list
    dataset= {
        "id": str(uuid),
        "ts": int(time.time()), # timestamp of dataset is in seconds
        "msgs": messages_list
    }

    return dataset

def connect_mqtt():
    def on_connect(client, userdata, flags, rc):
        if rc == 0:
            logger.info("sucessfully connected to MQTT Broker")
        else:
            logger.error("failed to connect to MQTT Broker, return code %d\n", rc)
    # Set Connecting Client ID
    client = mqtt_client.Client(client_id)
    # client.username_pw_set(username, password)
    client.on_connect = on_connect
    client.connect(broker, port)
    return client

def subscribe(client: mqtt_client):
    def on_message(client, userdata, msg):
        logger.debug("received MQTT with payload: {}".format(msg.payload.decode()))
        message_data ={
            "msg_ts_ms": int(time.time()*1000.0), # the timestamp for messages is in milliseconds
            "msg":msg,
        }
        mqtt_msg_queue.put(message_data) #put event data in queue
    
    logger.debug("subscribing to topic {}".format(topic))
    client.subscribe(topic,qos=1) #set QOS depending on your network/needed reliability
    client.on_message = on_message
########################################################################

if len(sys.argv) < 4:
    print("usage:")
    print("  python3 example-client-mqtt.py <env> <UUID> <ubirch-auth-token>")
    sys.exit(0)

env = sys.argv[1]
uuid = UUID(hex=sys.argv[2])
auth = sys.argv[3]

client = connect_mqtt()
subscribe(client)

last_send = time.time()
while True:
    client.loop()
    if time.time()-last_send > 10:
        last_send = time.time()
        print("---DATA IN BUFFER---")
        print(json.dumps(get_dataset()))
        print()

sys.exit(0)

# create a keystore for the device
keystore = ubirch.KeyStore("mqtt-device.jks", "keystorepassword")

# create an instance of the protocol with signature saving
protocol = Proto(keystore, uuid)

# create an instance of the UBIRCH API and set the auth token
api = ubirch.API(env=env)
api.set_authentication(uuid, auth)

# register the public key at the UBIRCH key service
if not api.is_identity_registered(uuid):
    certificate = keystore.get_certificate(uuid)
    key_registration = protocol.message_signed(uuid, UBIRCH_PROTOCOL_TYPE_REG, certificate)
    r = api.register_identity(key_registration)
    if r.status_code == codes.ok:
        logger.info("{}: public key registered".format(uuid))
    else:
        logger.error("{}: registration failed".format(uuid))
        sys.exit(1)

# create a message like being sent to the customer backend
# include an ID and timestamp in the data message to ensure a unique hash
dataset = get_dataset()
# >> send data to customer backend <<
#TODO: save data locally for tests (no customer backend atm)

# create a compact rendering of the message to ensure determinism when creating the hash
serialized = json.dumps(dataset, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode()

# hash the message
message_hash = hashlib.sha512(serialized).digest()
logger.info("message hash: {}".format(binascii.b2a_base64(message_hash, newline=False).decode()))

# create a new chained protocol message with the message hash
upp = protocol.message_chained(uuid, UBIRCH_PROTOCOL_TYPE_BIN, message_hash)
logger.info("UPP: {}".format(binascii.hexlify(upp).decode()))

# send chained protocol message to UBIRCH authentication service
r = api.send(uuid, upp)
if r.status_code == codes.ok:
    logger.info("UPP successfully sent. response: {}".format(binascii.hexlify(r.content).decode()))
else:
    logger.error("sending UPP failed! response: ({}) {}".format(r.status_code, binascii.hexlify(r.content).decode()))
    sys.exit(1)

# verify the backend response
try:
    protocol.message_verify(r.content)
    logger.info("backend response signature successfully verified")
except Exception as e:
    logger.error("backend response signature verification FAILED! {}".format(repr(e)))
    sys.exit(1)

# save last signature
protocol.persist(uuid)
