import binascii
import hashlib
import json
import logging
import pickle
import random
import sys
import time
import os
import persistqueue #TODO: add to the requirements
from paho.mqtt import client as mqtt_client #TODO: add to the requirements file
from uuid import UUID

from ed25519 import VerifyingKey
from requests import codes

import ubirch
from ubirch.ubirch_protocol import UBIRCH_PROTOCOL_TYPE_REG, UBIRCH_PROTOCOL_TYPE_BIN

logging.basicConfig(format='%(asctime)s %(name)20.20s %(levelname)-8.8s %(message)s', level=logging.INFO)
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
broker = '192.168.1.81'
port = 1883
topic = "/ubirch/rsconnectdata/temperature"
mqtt_client_id = f'ubirch-mqtt-client-example'

def mqtt_connect():
    def on_connect(client, userdata, flags, rc):
        if rc == 0:
            logger.info("sucessfully connected to MQTT Broker")
        else:
            logger.error("failed to connect to MQTT Broker, return code %d\n", rc)
    # Set Connecting Client ID
    client = mqtt_client.Client(mqtt_client_id)
    # client.username_pw_set(username, password)
    client.on_connect = on_connect
    client.connect(broker, port)
    return client

def mqtt_subscribe(client: mqtt_client):
    def on_message(client, userdata, msg):
        logger.debug("received MQTT with payload: {}".format(msg.payload.decode()))
        queueMessage(msg)
    
    logger.debug("subscribing to topic {}".format(topic))
    client.subscribe(topic,qos=1) #set QOS depending on your network/needed reliability
    client.on_message = on_message
########################################################################

########################################################################
# queueing/sealing/sending section
PATH_MACHINEDATA_QUEUE = "/tmp/machinedataqueue"
machinedata = persistqueue.Queue(PATH_MACHINEDATA_QUEUE)
def queueMessage(msgObject):
    """
    Receives a machine data message from the protocol callbacks and formats it into a dict. Also adds metainformation like timestamp.
    Then appends the message dict to the queue.
    """
    queueingTime = int(time.time()*1000.0) # remember the timestamp when the message was queued in milliseconds

    #convert message contents to dict depending on type, we need a dict for pickling/file backup queue support
    msgType = type(msgObject).__name__
    if msgType == "MQTTMessage":
        message_content_dict = {
            "msg_topic": msgObject.topic,
            "msg_payload": msgObject.payload.decode("utf-8"), #TODO: assumes that the payload is always UTF-8 string. add check/handling or different encoding e.g. base 64
            "msg_qos": msgObject.qos,
            "msg_retain": msgObject.retain,
            "msg_mid": msgObject.mid
        }
    else:
        logger.error("queueMessage: unknown type of message for queueing: {}".format(msgType))
        raise NotImplementedError

    #assemble message dict from metadata and message content
    message_dict ={
        "msg_queue_ts_ms": queueingTime, 
        "msg_type":msgType,
        "msg_content":message_content_dict
    }

    logger.debug("queueing message: {}".format(message_dict))
    machinedata.put(message_dict)

    return

PATH_SEND_QUEUE = "/tmp/sendqueue"
backenddata = persistqueue.Queue(PATH_SEND_QUEUE)
def sealDatablock(ubirchProtocol:Proto, uuid:UUID):
    """
    Gets data from the machine data queue, aggregates it into a datablock (string json in this example) and creates a matching upp (bytes) for sealing the data.
    Then puts both block and upp into the sending queue and removes the data from the machinedata queue.
    """
    if machinedata.empty(): #if there is no data available, do not create a block
        return
    creationTime = int(time.time()) # remember the timestamp when the block was created and sealed in seconds

    #get data from queue and assemble message list
    messages_list = [] #this will become a list of the message dictionaries
    while not machinedata.empty():
        messages_list.append(machinedata.get())

    #add block metadata
    datablock_dict= {
        "id": str(uuid),
        "ts": creationTime, # timestamp of datablock creation in seconds
        "msgs": messages_list
    }

    #convert to json: create a compact rendering of the message to ensure determinism when creating the hash later
    datablock_json = json.dumps(datablock_dict, separators=(',', ':'), sort_keys=True, ensure_ascii=False)#.encode()
    logger.info("created datablock with {} messages".format(len(messages_list)))
    logger.debug("datablock content: {}".format(datablock_json))

    # hash the data block
    message_hash = hashlib.sha512(datablock_json.encode('utf-8')).digest()
    logger.info("datablock hash: {}".format(binascii.b2a_base64(message_hash, newline=False).decode()))

    # create a new chained protocol message with the message hash
    upp = ubirchProtocol.message_chained(uuid, UBIRCH_PROTOCOL_TYPE_BIN, message_hash)

    # add data to send queue and remove it from machinedata queue
    # we use a tupel to indicate data type id (used in send funtion later to determine endpoint)
    backenddata.put(("datablock",datablock_json))
    backenddata.put(("upp",upp))
    machinedata.task_done    
    # persist the last signature to disk, as the data and upp is safely stored now
    protocol.persist(uuid)

    logger.info("UPP: {}".format(binascii.hexlify(upp).decode()))

    return

def sendData(protocol:Proto, api:ubirch.API):
    logger.info("attempting to send {} backend data items".format(backenddata.qsize()))
    sendFails = 0
    while sendFails < 10:

        if backenddata.empty(): # we managed to send all items
            return True
        
        # get and send next item
        (dataType, data) = backenddata.get()
        if dataType == "upp":
            if sendUPP(protocol,api,data):
                backenddata.task_done()
                sendFails = 0
            else:
                sendFails += 1
        elif dataType == "datablock":
            if sendDatablock(data):
                backenddata.task_done()
                sendFails = 0
            else:
                sendFails += 1
        else:
            logger.error("sending data type '{}' not implemented".format(dataType))
            raise NotImplementedError

    # if we reach this point sending failed too often
    return False

def sendUPP(protocol:Proto, api:ubirch.API, upp:bytes)-> bool:
    """
    Sends UPP to ubirch backend, returns true in case of success.
    """
    # send upp to UBIRCH backend service
    r = api.send(uuid, upp)
    if r.status_code == codes.ok:
        logger.info("UPP successfully sent. response: {}".format(binascii.hexlify(r.content).decode()))
    else:
        logger.error("sending UPP failed! response: ({}) {}".format(r.status_code, binascii.hexlify(r.content).decode()))
        return False

    # verify the backend response
    try:
        protocol.message_verify(r.content)
        logger.info("backend response signature successfully verified")
    except Exception as e:
        logger.error("backend response signature verification FAILED! {}".format(repr(e)))
        raise Exception("ubirch backend response signature verification failed")

    return True

PATH_SENT_DATABLOCKS = "/tmp/sentdatablocks"
def sendDatablock(datablock:str):
    storeLocation = PATH_SENT_DATABLOCKS
    logger.error("No customer data backend implemented. Storing data locally in {}".format(storeLocation))
    #we use the current (=storage time) timestamp as filename for a simple mock backend
    filename = str(int(time.time())) + '.json'
    fullpath = os.path.join(PATH_SENT_DATABLOCKS, filename)

    directory = os.path.dirname(fullpath)
    if not os.path.exists(directory):
        os.mkdir(directory)

    with open(fullpath, 'w') as output_file:
        output_file.write(datablock)

    return True


########################################################################



if len(sys.argv) < 4:
    print("usage:")
    print("  python3 example-client-mqtt.py <env> <UUID> <ubirch-auth-token>")
    sys.exit(0)

env = sys.argv[1]
uuid = UUID(hex=sys.argv[2])
auth = sys.argv[3]

mqtt_client = mqtt_connect()
mqtt_subscribe(mqtt_client)

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

lastSealDatablock = time.time()
while True:
    mqtt_client.loop()

    if time.time()-lastSealDatablock > 10: #time for sealing next block?        
        sealDatablock(protocol,uuid)
        lastSealDatablock = time.time()

    if not backenddata.empty(): # data for sending available?
        if not sendData(protocol,api):
            logger.error("sending backend data failed")
