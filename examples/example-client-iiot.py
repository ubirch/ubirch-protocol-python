import binascii
import hashlib
import json
import logging
import pickle
import random
import sys
import time
import os
import shelve #TODO: add to requirements
import persistqueue #TODO: add to the requirements
from paho.mqtt import client as mqtt_client #TODO: add to the requirements file
from asyncua.sync import Client as opcua_client #TODO: add to requirements (pip3 install asyncua)
from uuid import UUID

from ed25519 import VerifyingKey
from requests import codes

import ubirch
from ubirch.ubirch_protocol import UBIRCH_PROTOCOL_TYPE_REG, UBIRCH_PROTOCOL_TYPE_BIN

logging.getLogger("asyncua").setLevel(logging.WARNING) # reduce verbosity of the import opc ua module
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
                logger.info("ubirch-protocol: loaded {} known signatures".format(len(signatures)))
                self.set_saved_signatures(signatures)
        except FileNotFoundError:
            logger.warning("ubirch-protocol: no existing saved signatures")
            pass

    def _sign(self, uuid: UUID, message: bytes) -> bytes:
        return self.__ks.find_signing_key(uuid).sign(message)

    def _verify(self, uuid: UUID, message: bytes, signature: bytes):
        return self.__ks.find_verifying_key(uuid).verify(signature, message)


########################################################################

########################################################################
# OPC-UA section
# partly based on the examples from https://github.com/FreeOpcUa/opcua-asyncio
OPCUA_ADDRESS = "opc.tcp://192.168.1.81:4840/"
OPCUA_NAMESPACE = "urn:wago-com:codesys-provider"
OPCUA_NODES = [ "|var|RSConnect.Application.GVL_OPCUA.Input1",
                "|var|RSConnect.Application.GVL_OPCUA.Input2",
                "|var|RSConnect.Application.GVL_OPCUA.output1_visu",
                "|var|RSConnect.Application.GVL_OPCUA.counter_input",
                "|var|RSConnect.Application.GVL_OPCUA.counter_output",
                "|var|RSConnect.Application.GVL_OPCUA.temperature1"]

class OPCUASubscriptionCallback(object):

    """
    Subscription Handler. To receive events from server for a subscription
    data_change and event methods are called directly from receiving thread.
    Do not do expensive, slow or network operation there. Create another
    thread if you need to do such a thing
    """

    def datachange_notification(self, node, val, data):
        logger.info(f"OPC-UA: received notification: node: {node}, value: {val}")
        logger.debug(data.subscription_data)
        logger.debug(data.monitored_item)
        queueMessage(data) # hand the received data over to the queue function
        


def opcua_connect():

    client = opcua_client(OPCUA_ADDRESS)
    try:
        client.connect()
        logger.info("OPC-UA: successfully connected")
    except Exception as e:
        logger.error(f"OPC-UA connection failed: {repr(e)}")

    return client

def opcua_subscribe(client:opcua_client):

    # get the namespace index
    idx = client.get_namespace_index(OPCUA_NAMESPACE)

    #set up subscription basics
    subscriptionHandler = OPCUASubscriptionCallback()
    sub = client.create_subscription(50, subscriptionHandler)

    # get the nodes to subscribe to and do the subsciption
    for nodename in OPCUA_NODES:
        node = client.get_node(f"ns={idx};s=" + nodename)
        logger.info(f"OPC-UA: subscribing to node: {nodename}")
        handle = sub.subscribe_data_change(node)
        time.sleep(0.1)

########################################################################


########################################################################
# Functions for managing MQTT data
# MQTT funtions partly based on https://www.emqx.io/blog/how-to-use-mqtt-in-python
broker = '192.168.1.81'
port = 1883
topics = ["/ubirch/rsconnectdata/temperature"]
mqtt_client_id = f'ubirch-client-example'

def mqtt_connect():
    def on_connect(client, userdata, flags, rc):
        if rc == 0:
            logger.info("MQTT: successfully connected to broker")
        else:
            logger.error("MQTT: failed to connect to broker, return code %d\n", rc)
    # Set Connecting Client ID
    client = mqtt_client.Client(mqtt_client_id)
    # client.username_pw_set(username, password)
    client.on_connect = on_connect
    client.connect(broker, port)
    return client

def mqtt_subscribe(client: mqtt_client):
    def on_message(client, userdata, msg):
        logger.info("MQTT: received message: topic: {}, payload: {}".format(msg.topic, msg.payload.decode()))
        queueMessage(msg)
    
    for topic in topics:
        logger.info("MQTT: subscribing to topic {}".format(topic))
        client.subscribe(topic,qos=1) #set QOS depending on your network/needed reliability
    client.on_message = on_message
########################################################################

########################################################################
# queueing/sealing/sending section
PATH_MACHINEDATA_QUEUE = "machinedataqueue"
machinedata = persistqueue.Queue(PATH_MACHINEDATA_QUEUE)
def queueMessage(msgObject):
    """
    Receives a machine data message from the protocol callbacks and formats it into a dict. Also adds metainformation like timestamp.
    Then appends the message dict to the queue.
    """
    queueingTime = int(time.time()*1000.0) # remember the timestamp when the message was queued in milliseconds

    #convert message contents to dict depending on type, we need a dict for pickling/file backup queue support
    msgType = type(msgObject).__name__
    # MQTT
    if msgType == "MQTTMessage":
        message_content_dict = {
            "msg_topic": msgObject.topic,
            "msg_payload": msgObject.payload.decode("utf-8"), #TODO: assumes that the payload is always UTF-8 string. add check/handling or different encoding e.g. base 64
            "msg_qos": msgObject.qos,
            "msg_retain": msgObject.retain,
            "msg_mid": msgObject.mid
        }
    # OPC-UA
    elif msgType == "DataChangeNotif": # TODO: maybe find a way to make it more clear that this type belongs to OPC-UA?
        message_content_dict = {
            "msg_node": str(msgObject.subscription_data.node),
            "msg_value": msgObject.monitored_item.Value.Value.Value,
            "msg_src_ts_ms": int(msgObject.monitored_item.Value.SourceTimestamp.timestamp()*1000), # source timestamp with ms precision
            "msg_srv_ts_ms": int(msgObject.monitored_item.Value.ServerTimestamp.timestamp()*1000), # server timestamp with ms precision
            "msg_status": str(msgObject.monitored_item.Value.StatusCode)
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

PATH_SEAL_QUEUE = "sealqueue"
sealQueue = persistqueue.Queue(PATH_SEAL_QUEUE)
def aggregateData():
    """
    Gets data from the machine data queue and aggregates it into a datablock with some metadata.
    Then puts the block into the sealing queue and removes the data from the machinedata queue.
    """
    BLOCKNR_NAME = 'blocknumber'

    if machinedata.empty(): #if there is no data available, do not create a new block
        logger.info("no data to aggregate")
        return

    blockCreationTime = int(time.time()) # remember the timestamp when the block was created (in seconds)

    #get data from queue and assemble message list
    messages_list = [] #this will become a list of the message dictionaries
    while not machinedata.empty():
        messages_list.append(machinedata.get())

    #load block number from disk
    blocknumber = 0
    try:
        with shelve.open(BLOCKNR_NAME) as db:
            blocknumber = db[BLOCKNR_NAME]
            blocknumber += 1
    except Exception as e:
        logger.error("loading previous block number failed, defaulting to zero. Exception was: {}".format(repr(e)))        

    #add block metadata
    datablock_dict= {
        "block_nr": blocknumber,
        "block_ts": blockCreationTime, # timestamp of datablock creation in seconds
        "block_msgs": messages_list
    }

    logger.info("created datablock with {} messages".format(len(messages_list)))
    logger.debug("datablock content: {}".format(datablock_dict))

    # put new block into sealing queue and persist our changes to the machinedata queue and block number
    sealQueue.put(datablock_dict)
    with shelve.open(BLOCKNR_NAME) as db:
        db[BLOCKNR_NAME] = blocknumber
    machinedata.task_done()

    return

PATH_SEND_BLOCK_QUEUE = "sendblockqueue"
sendDatablocksQueue = persistqueue.Queue(PATH_SEND_BLOCK_QUEUE)
def sealDatablocks(protocol:Proto, api:ubirch.API, uuid:UUID):
    """
    Takes blocks of aggregated data from the seal queue, serializes the data, sends a matching UPP to the ubirch backend,
    and finally adds the (now sealed and anchored) serialized data to the "customer backend" sending queue.
    Returns when the queue is empty or sending the UPP fails. Sending will then be tried again on next run.
    """
    while not sealQueue.empty():
        # get data block from seal queue, keep a backup for putting back in case of failure
        original_datablock_dict = sealQueue.get()
        datablock_dict = original_datablock_dict

        logger.info("sealing data block number {}".format(datablock_dict['block_nr']))

        # add metadata
        sealTime = int(time.time()) #TODO: check if we might need ms precision for seal timestamp
        datablock_dict['seal_ts'] = sealTime
        datablock_dict['uuid'] = str(uuid)

        # convert to json: create a compact rendering of the message to ensure determinism when creating the hash later
        datablock_json = json.dumps(datablock_dict, separators=(',', ':'), sort_keys=True, ensure_ascii=False)

        # make sure we can go back to this point in the UPP signature chaining later in case of problems with the UPP/sending
        protocol.persist(uuid)

        UPPsentOK = sendUPP(protocol, api, uuid, datablock_json)

        if UPPsentOK == True:
            #everything is OK: queue sealed customer data for sending later and persist the last signature of the sent UPP
            sendDatablocksQueue.put(datablock_json)
            protocol.persist(uuid)
            sealQueue.task_done() # persist our changes to the sealing queue
        elif UPPsentOK == False:
            # we are unable to send the UPP (at the moment), put block back and restore UPP signature chain, then return
            sealQueue.put(original_datablock_dict)
            protocol.load(uuid)
            return
        else:
            raise ValueError
            
    return

def sendUPP(protocol:Proto, api:ubirch.API, uuid:UUID, datablock_json:str)-> bool:
    """
    Sends UPP to ubirch backend, returns true in case of success response from
    backend. Also reasonably handles some of the most important backend responses/errors.
    """
    MAX_FAILS = 3

    if not isinstance(datablock_json, str):
        raise ValueError("Expected serialized json string for creating UPP")

    # hash the data block
    block_hash = hashlib.sha512(datablock_json.encode('utf-8')).digest()

    logger.info("sending UPP for data block with hash: {}".format(binascii.b2a_base64(block_hash, newline=False).decode()))
    logger.debug("datablock serialized content: {}".format(datablock_json))

    # create a new chained protocol message with the data block hash
    # we can only do this exactly once here, as persisting the signature chain is handled
    # in the calling function, and it expects only one new chained UPP to be generated
    upp = protocol.message_chained(uuid, UBIRCH_PROTOCOL_TYPE_BIN, block_hash)
    logger.debug("UPP: {}".format(binascii.hexlify(upp).decode()))

    #send the UPP to the ubirch backend
    fails = 0
    while fails < MAX_FAILS:
        try:
            # send upp to UBIRCH backend service
            r = api.send(uuid, upp)
            if r.status_code == 200: # backend says everything was OK
                logger.debug("'OK' backend response to UPP: {}".format(binascii.hexlify(r.content).decode()))
                try: # to verify the backend response                
                    unpackedResponseUPP = protocol.message_verify(r.content)
                    logger.info("backend response signature successfully verified")
                    logger.debug("unpacked response UPP: {}".format(unpackedResponseUPP))
                    
                    #TODO: check that signature from backend response actually matches signature of sent UPP
                    
                    # all checks passed, return success
                    logger.info("UPP successfully sent")
                    return True
                except Exception as e:
                    logger.error("backend response verification FAILED! {}".format(repr(e)))
            elif r.status_code == 409: # conflict: UPP with this hash already exists
                if backendUPPIdentical(block_hash,upp,api):
                    logger.warning("identical UPP was already present in backend")
                    return True # this exact UPP is already at backend, we are done
                else:
                    logger.error("sending UPP failed: UPP hash already in use")
                    # hash collision: there is a different UPP already with this hash, so we cannot anchor this UPP,
                    # we will try again later (which should work because the new seal timestamp leads to a new hash)
                    return False 
            else:
                logger.error("sending UPP failed! response: ({}) {}".format(r.status_code, binascii.hexlify(r.content).decode()))
        except Exception as e:
            logger.error("sending UPP failed: {}".format(repr(e)))
        fails += 1
    
    #at this point we have used up all our tries, give up
    return False

def backendUPPIdentical(hash: bytes, upp: bytes, api: ubirch.API) -> bool:
    """
    NOT IMPLEMENTED.
    Checks if a UPP with a certain hash is already in backend and identical to the provided UPP.
    Returns true or false. Must check backend response signature.
    """
    #TODO: implement
    raise NotImplementedError

def sendDatablocks():
    """
    Sends all previously sealed and anchored data waiting in the queue to the customer backend.
    """
    logger.info("attempting to send {} data blocks to customer backend".format(sendDatablocksQueue.qsize()))
    sendFails = 0
    while sendFails < 3:

        if sendDatablocksQueue.empty(): # we managed to send all items
            logger.info("all data blocks sent successfully")
            return True
        
        # get and send next item
        blockdata = sendDatablocksQueue.get()
        if sendDatablockToCustomerBackend(blockdata):
            sendDatablocksQueue.task_done()
            sendFails = 0
        else:
            sendFails += 1
            sendDatablocksQueue.put(blockdata) # put item back for next try
            logger.error("sending data block failed")


    # if we reach this point sending failed too often
    logger.error("giving up on sending data blocks to customer backend")
    return False

PATH_SENT_DATABLOCKS = "sentdatablocks"
def sendDatablockToCustomerBackend(datablock:str):
    """
    A mock send function to simulate the customer backend.
    """
    storeLocation = PATH_SENT_DATABLOCKS
    logger.warning("No customer data backend implemented. Storing data locally in {}".format(storeLocation))
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

logger.info("client started")

env = sys.argv[1]
uuid = UUID(hex=sys.argv[2])
auth = sys.argv[3]

logger.info("OPC-UA: connecting")
opcua_client = opcua_connect()
opcua_subscribe(opcua_client)

logger.info("MQTT: connecting")
mqtt_client = mqtt_connect()
mqtt_subscribe(mqtt_client)

# create a keystore for the device
keystore = ubirch.KeyStore("mqtt-device.jks", "keystorepassword")

# create an instance of the protocol with signature saving
protocol = Proto(keystore, uuid)

# create an instance of the UBIRCH API and set the auth token
api = ubirch.API(env=env)
api.set_authentication(uuid, auth)

logger.info("ubirch-protocol: checking key registration")
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

logger.info("starting main loop")
lastAggregateData = time.time()
lastSealBlocks = time.time()

try:
    while True:
        mqtt_client.loop()

        if time.time()-lastAggregateData > 10: #time for aggregating received data into next block?        
            aggregateData()
            lastAggregateData = time.time()

        if time.time()-lastSealBlocks > 10: #time for sealing and anchoring the blocks?        
            if not sealQueue.empty():
                sealDatablocks(protocol,api,uuid)
            else:  
                logger.info("sealing time but no data to seal")
            lastSealBlocks = time.time()

        if not sendDatablocksQueue.empty(): # data for sending to customer backend available?
            sendDatablocks()
except KeyboardInterrupt:
    pass
except Exception as e:
    logger.error(f"Exception during main loop: {repr(e)}")
    raise

logger.info("shutting down")
mqtt_client.disconnect()
opcua_client.disconnect()
