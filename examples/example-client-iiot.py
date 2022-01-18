import binascii
import hashlib
import json
import logging
import pickle
import random
import sys
import time
import os
import getpass
import shelve
import persistqueue
from paho.mqtt import client as MqttClient
from asyncua.sync import Client as OpcuaClient
from asyncua.sync import ThreadLoop
from uuid import UUID

from ed25519 import VerifyingKey
from requests import codes

import ubirch
from ubirch.ubirch_protocol import UBIRCH_PROTOCOL_TYPE_REG, UBIRCH_PROTOCOL_TYPE_BIN

logging.getLogger("asyncua").setLevel(logging.WARNING) # reduce verbosity of the import opc ua module
logging.basicConfig(format='%(asctime)s %(name)20.20s %(levelname)-8.8s %(message)s', level=logging.INFO)
logger = logging.getLogger()


########################################################################
# uirch protocol section
class Proto(ubirch.Protocol):
    """
    Implements the ubirch-protocol with signing and saving the signatures.
    Accepts a keystore for saving key pairs, the UUID of the device, and a path where to store
    persistent data, i.e. the last used signatures for chaining UPPs.
    """

    # public keys and UUIDs of the ubirch backend for verification of responses
    UUID_DEV = UUID(hex="9d3c78ff-22f3-4441-a5d1-85c636d486ff")
    PUB_DEV = VerifyingKey("a2403b92bc9add365b3cd12ff120d020647f84ea6983f98bc4c87e0f4be8cd66", encoding='hex')
    UUID_DEMO = UUID(hex="07104235-1892-4020-9042-00003c94b60b")
    PUB_DEMO = VerifyingKey("39ff77632b034d0eba6d219c2ff192e9f24916c9a02672acb49fd05118aad251", encoding='hex')
    UUID_PROD = UUID(hex="10b2e1a4-56b3-4fff-9ada-cc8c20f93016")
    PUB_PROD = VerifyingKey("ef8048ad06c0285af0177009381830c46cec025d01d86085e75a4f0041c2e690", encoding='hex')

    def __init__(self, key_store: ubirch.KeyStore, uuid: UUID, persistent_storage_path: str = "") -> None:
        super().__init__()
        self.__ks = key_store
        self._persistent_storage_path = persistent_storage_path

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
        """Saves the last used signatures to disk."""
        signatures = self.get_saved_signatures()
        with open(os.path.join(self._persistent_storage_path, uuid.hex+".sig"), "wb") as f:
            pickle.dump(signatures, f)

    def load(self, uuid: UUID):
        """Loads the last used signatures from disk. Issues a warning if file not found but continues."""
        try:
            with open(os.path.join(self._persistent_storage_path, uuid.hex+".sig"), "rb") as f:
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
class OPCUASubscriptionCallback(object):
    """
    This Subscription Handler handles reception of OPC-UA messages.
    To receive events from a server for a subscription
    data_change and event methods are called directly from the receiving thread.
    Do not do expensive, slow or network operation there. Create another
    thread if you need to do such a thing
    """

    def datachange_notification(self, node, val, data):
        logger.info(f"OPC-UA: received notification: node: {node}, value: {val}")
        logger.debug(data.subscription_data)
        logger.debug(data.monitored_item)
        queue_message(data) # hand the received data over to the queue function

def opcua_connect(opcua_address:str)-> OpcuaClient:
    """Connect to an OPC-UA server at the given address. Returns client instance."""

    logger.info(f"OPC-UA: connecting to {opcua_address}")
    client = OpcuaClient(opcua_address)
    try:
        client.connect()
        logger.info("OPC-UA: successfully connected")
    except Exception as e:
        logger.error(f"OPC-UA connection failed: {repr(e)}")
        client.tloop.stop() # stop the client threadloop to avoid hang on exit
        raise

    return client

def opcua_subscribe(client:OpcuaClient, namespace:str, nodes: list):
    """
    Subscribes to all nodes in the given list using the given client instance and namespace.
    The nodes are expected as identifiers without leading 'ns=...' or 's=...' (These are added automatically.).
    Example node name: '|var|Manufacturer.Application.GVL_OPCUA.Input1'.
    """

    # get the namespace index
    idx = client.get_namespace_index(namespace)

    # set up subscription basics
    subscriptionHandler = OPCUASubscriptionCallback()
    sub = client.create_subscription(50, subscriptionHandler)

    # get the nodes to subscribe to and do the subsciption
    for nodename in nodes:
        node = client.get_node(f"ns={idx};s=" + nodename)
        logger.info(f"OPC-UA: subscribing to node: {nodename}")
        handle = sub.subscribe_data_change(node)
        time.sleep(0.1)

########################################################################


########################################################################
# MQTT section
# MQTT funtions partly based on https://www.emqx.io/blog/how-to-use-mqtt-in-python
def mqtt_connect(address:str, port:int, client_id:str, enable_tls:bool, username: str = None, password:str = None) -> MqttClient:
    """
    Connect to an MQTT broker using the address, port and client ID. Client ID must be unique on broker side.
    If username is set, username and password parameter are used for authenticating by passing them to paho mqtt username_pw_set().
    If enable_tls is true, paho mqtt set_tls() is called before starting the connection.
    Returns the client instance.
    """
    def on_connect(client, userdata, flags, rc):
        if rc == 0:
            logger.info("MQTT: successfully connected to broker")
            mqtt_subscribe(client, MQTT_TOPICS) # TODO: find a better way of resubscribing without using global topics variable
        else:
            logger.error(f"MQTT: failed to connect to broker, return code {rc} ({MqttClient.error_string(rc)})")

    def on_disconnect(client, userdata, rc):
        if rc !=0:
            logger.error("MQTT: unexpected disconnect")

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

    logger.info(f"MQTT: connecting to {address+' port '+str(port)+', '+tls_state_string}")
    client.connect(address, port)
    client.loop_start() # make mqtt client start processing traffic on its own in seperate thread
    return client

def mqtt_subscribe(client: MqttClient, topics: list):
    """Subscribe to all topics from the topics list using the given client."""
    def on_message(client, userdata, msg):
        # handle non-printable data output
        try:
            payload_string = msg.payload.decode('utf-8')
        except UnicodeDecodeError:
            payload_string = binascii.b2a_hex(msg.payload)
        logger.info("MQTT: received message: topic: {}, payload: {}".format(msg.topic, payload_string))
        queue_message(msg)
    
    for topic in topics:
        logger.info("MQTT: subscribing to topic {}".format(topic))
        client.subscribe(topic,qos=1) #set QOS depending on your network/needed reliability
    client.on_message = on_message
########################################################################

########################################################################
# queueing/sealing/sending section
def queue_message(msg_object):
    """
    Receives a machine data message from the protocol callbacks and formats it into a dict according to its type.
    Also adds metainformation like timestamp. Then appends the message dict to the machine data queue.
    """
    queueing_time = int(time.time()*1000.0) # remember the timestamp when the message was queued in milliseconds

    # convert message contents to dict depending on type, we need a dict for pickling/file backup queue support
    msg_type = type(msg_object).__name__
    # MQTT
    if msg_type == "MQTTMessage":
        # change this depending on whether your payload is string or bytes 
        payload_string = msg_object.payload.decode('utf-8')
        #payload_string = msg_object.payload.hex()

        message_content_dict = {
            "msg_topic": msg_object.topic,
            "msg_payload": payload_string, 
            "msg_qos": msg_object.qos,
            "msg_retain": msg_object.retain,
            "msg_mid": msg_object.mid
        }
    # OPC-UA
    elif msg_type == "DataChangeNotif": # <-- This is an asyncua OPC-UA DataChangeNotification, whose object is a bit strangely named...
        message_content_dict = {
            "msg_node": str(msg_object.subscription_data.node),
            "msg_value": msg_object.monitored_item.Value.Value.Value,
            "msg_src_ts_ms": int(msg_object.monitored_item.Value.SourceTimestamp.timestamp()*1000), # source timestamp with ms precision
            "msg_srv_ts_ms": int(msg_object.monitored_item.Value.ServerTimestamp.timestamp()*1000), # server timestamp with ms precision
            "msg_status": str(msg_object.monitored_item.Value.StatusCode)
        }
    else:
        logger.error("queue_message: unknown type of message for queueing: {}".format(msg_type))
        raise NotImplementedError

    # assemble message dict from metadata and message content
    message_dict ={
        "msg_queue_ts_ms": queueing_time, 
        "msg_type":msg_type,
        "msg_content":message_content_dict
    }

    logger.debug("queueing message: {}".format(message_dict))
    machinedata.put(message_dict)

    return

def aggregate_data(uuid: UUID,persistent_storage_path:str):
    """
    Gets data from the machine data queue and aggregates it into a data block with some metadata.
    Then puts the block into the sealing queue and removes the data from the machinedata queue.
    The uuid is used to build the filename for persisting the block number.
    Persisten storage path ist the folder where to save the block number.
    """
    BLOCKNR_NAME = uuid.hex+'-blocknumber'
    BLOCKNR_FULLPATH = os.path.join(persistent_storage_path,BLOCKNR_NAME)

    if machinedata.empty(): # if there is no data available, do not create a new block
        logger.info("no data to aggregate available")
        return

    block_creation_time = int(time.time()*1000) # remember the timestamp when the block was created (in milliseconds)

    # get data from queue and assemble message list
    messages_list = [] #this will become a list of the message dictionaries
    while not machinedata.empty():
        messages_list.append(machinedata.get())

    # load block number from disk
    blocknumber = 1 # number for very first block
    try:
        with shelve.open(BLOCKNR_FULLPATH) as db:
            blocknumber = db[BLOCKNR_NAME]
            blocknumber += 1
    except Exception as e:
        logger.error("loading previous block number failed, defaulting to one. Exception was: {}".format(repr(e)))        

    # add block metadata
    datablock_dict= {
        "block_nr": blocknumber,
        "block_ts_ms": block_creation_time, # timestamp of data block creation in milliseconds
        "block_msgs": messages_list
    }

    logger.info(f"created data block number {blocknumber} with {len(messages_list)} messages")
    logger.debug("data block content: {}".format(datablock_dict))

    # put new block into sealing queue and persist our changes to the machinedata queue and block number
    seal_queue.put(datablock_dict)
    with shelve.open(BLOCKNR_FULLPATH) as db:
        db[BLOCKNR_NAME] = blocknumber
    machinedata.task_done()

    return

def seal_datablocks(protocol:Proto, api:ubirch.API, uuid:UUID):
    """
    Takes blocks of aggregated data from the seal queue, serializes the data, sends a matching UPP to the ubirch backend,
    and finally adds the (now sealed and anchored) serialized data to the "customer backend" sending queue.
    Returns when the queue is empty or sending the UPP fails. Sending will then be tried again on next call.
    """
    global seal_queue
    if seal_queue.empty(): #if there is no data available, return
        logger.info("no data to seal available")
        return
    
    logger.info("attempting to seal {} data blocks".format(seal_queue.qsize()))
    while not seal_queue.empty():
        # get data block from seal queue
        datablock_dict = seal_queue.get()

        logger.info("sealing data block number {}".format(datablock_dict['block_nr']))

        # add metadata
        seal_time = int(time.time()*1000) #ms precision seal timestamp
        datablock_dict['seal_ts_ms'] = seal_time
        datablock_dict['uuid'] = str(uuid)

        # convert to json: create a compact rendering of the message to ensure determinism when creating the hash later
        datablock_json = json.dumps(datablock_dict, separators=(',', ':'), sort_keys=True, ensure_ascii=False)

        # make sure we can go back to this point in the UPP signature chaining later in case of problems with the UPP/sending
        protocol.persist(uuid)

        upp_sent_ok = send_UPP(protocol, api, uuid, datablock_json)

        if upp_sent_ok == True:
            # everything is OK: queue sealed customer data for sending later and persist the last signature of the sent UPP
            send_datablocks_queue.put(datablock_json)
            protocol.persist(uuid)
            seal_queue.task_done() # persist our changes to the sealing queue
        elif upp_sent_ok == False:
            # we are unable to send the UPP (at the moment), restore seal queue from file and restore UPP signature chain, then return

            # restore queue
            # TODO: the queue part is a bit hacky as we simply re-initiialize the queue from disk.
            # It would be better to just 'peek()' the element without removing it but that is not supported by persistqueue
            # Putting the element back via put() is also not an option, as this changes block order from e.g. 1,2,3 to 2,3,1 when sending
            # next time and that messes with the upp chain order. Might be worth asking for peek() implementation at the persistqueue repo.
            logger.warning('reloading seal queue from disk')
            seal_queue_path = seal_queue.path 
            seal_queue = persistqueue.Queue(seal_queue_path)

            # restore signature chain
            protocol.load(uuid)
            return
        else:
            raise ValueError
            
    return

def send_UPP(protocol:Proto, api:ubirch.API, uuid:UUID, datablock_json:str)-> bool:
    """
    Sends UPP to ubirch backend, returns true in case of success response from
    backend. Will retry a few (3) times before giving up. Also reasonably handles some
    of the most important backend responses/errors.
    """
    MAX_FAILS = 3

    if not isinstance(datablock_json, str):
        raise ValueError("Expected serialized json string for creating UPP")

    # hash the data block
    block_hash = hashlib.sha512(datablock_json.encode('utf-8')).digest()

    logger.info("sending UPP for data block with hash: {}".format(binascii.b2a_base64(block_hash, newline=False).decode()))
    logger.debug("data block serialized content: {}".format(datablock_json))

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
            r = api.send(uuid, bytes(upp))
            if r.status_code == 200: # backend says everything was OK
                logger.debug("'OK' backend response to UPP: {}".format(binascii.hexlify(r.content).decode()))
                try: # to verify the backend response     
                    #verify the signature of the backend response and unpack upp           
                    unpacked_response_UPP = protocol.message_verify(r.content)
                    logger.info("backend response signature successfully verified")
                    logger.debug("unpacked response UPP: {}".format(unpacked_response_UPP))
                    # extract prev signature field (must match sent upp signature)
                    backend_prev_signature = unpacked_response_UPP[2]
                    logger.debug(f"response UPP prev. signature: {backend_prev_signature}")
                    #get the signature of the sent upp by unpacking it
                    unpacked_sent_UPP = protocol.message_verify(upp)
                    sent_UPP_signature = unpacked_sent_UPP[-1]
                    logger.debug(f"sent UPP signature: {sent_UPP_signature}")

                    if sent_UPP_signature != backend_prev_signature:
                        raise Exception("UPP signature acknowledged by backend does not match sent UPP signature")
                    
                    logger.info("backend acknowledged UPP signature matches sent UPP signature")
                    
                    # all checks passed, return success
                    logger.info("UPP successfully sent")
                    return True
                except Exception as e:
                    logger.error("backend response verification FAILED! {}".format(repr(e)))
            elif r.status_code == 409: # conflict: UPP with this hash already exists
                logger.warning("received 409/conflict from backend")
                if backend_UPP_identical(block_hash,upp,api):
                    logger.warning("identical UPP was already present in backend")
                    return True # this exact UPP is already at backend, we are done
                else:
                    logger.error("sending UPP failed: UPP hash already in use by other UPP")
                    # hash collision: there is a different UPP already with this hash, so we cannot anchor this UPP,
                    # we will try again later (which should work because the new seal timestamp leads to a new hash)
                    return False 
            else: #all other status codes
                logger.error("sending UPP failed! response: ({}) {}".format(r.status_code, binascii.hexlify(r.content).decode()))
        except Exception as e:
            logger.error("sending UPP failed: {}".format(repr(e)))
        fails += 1
    
    # at this point we have used up all our tries, give up
    return False

def backend_UPP_identical(local_upp_hash: bytes, local_upp: bytes, api: ubirch.API) -> bool:
    """
    Checks if a UPP with a certain hash is already in backend and identical to the provided UPP.
    Returns true or false. TODO: check backend response signature/authenticity.
    """
    logger.debug(f"Checking for 'already at backend' for UPP with hash: {binascii.b2a_base64(local_upp_hash, newline=False).decode()}")
    response = api.verify(local_upp_hash,quick=True)
    if response.status_code == 200:
        try:
            upp_info = json.loads(response.content)
            logger.debug(f"Received UPP info from verify endpoint: {upp_info}")
            backend_upp = binascii.a2b_base64(upp_info['upp'])
            if backend_upp == local_upp:
                logger.debug("backend UPP is identical")
                return True
            else:
                logger.debug("backend UPP is different")
                return False

        except Exception as e:
            logger.error("error while checking local and backend UPP for equality")
            raise
    elif response.status_code == 404:
        raise Exception("No UPP with this hash found (404), can't check for equality.")
    else:
        raise Exception(f"Error when checking if UPP is already at backend. Response code: {response.status_code}, Response content: {repr(response.content)}")

def send_datablocks(destination:str)->bool:
    """
    Sends all previously sealed and anchored data waiting in the queue to the customer backend. Uses retries, aborts on 3 consecutive fails.
    When the mock customer backend (filesystem storage) is used, destination is the folder in which the data is stored.
    Returns true on success, false otherwise.
    """
    logger.info("attempting to send {} data blocks to customer backend".format(send_datablocks_queue.qsize()))
    send_fails = 0
    while send_fails < 3:

        if send_datablocks_queue.empty(): # we managed to send all items
            logger.info("all data blocks sent successfully")
            return True
        
        # get and send next item
        blockdata = send_datablocks_queue.get()
        if send_data_to_customer_backend(blockdata, destination):
            send_datablocks_queue.task_done()
            send_fails = 0
        else:
            send_fails += 1
            send_datablocks_queue.put(blockdata) # put item back for next try
            logger.error("sending data block failed")


    # if we reach this point sending failed too often
    logger.error("giving up on sending data blocks to customer backend")
    return False

def send_data_to_customer_backend(datablock:str,store_path: str)-> bool:
    """
    A mock send function to simulate the customer backend.
    Accepts the data block as a string (probably compact serialized JSON), and the storage path.
    Returns true in case of success, raises exception in case of failure.
    """
    logger.warning("No customer data backend implemented. Storing data locally.")
    # we use the current (= storage time) timestamp as filename for the simple mock backend
    filename = str(int(time.time()*1000)) + '.json' # msec timestamp plus pause to avoid duplicate filenames
    time.sleep(0.010)
    fullpath = os.path.join(store_path, filename)

    directory = os.path.dirname(fullpath)
    if not os.path.exists(directory):
        os.mkdir(directory)

    with open(fullpath, 'w') as output_file:
        logger.debug(f"Saving to {fullpath}")
        output_file.write(datablock)

    return True


########################################################################


#### start of main code section ###


if len(sys.argv) < 2:
    print("example usage:")
    print("  python3 example-client-iiot.py iiot-client-config.json")
    print("  See iiot-client-config_example.json for an example config.")
    sys.exit(0)

logger.info("client started")

# configuration loading and general setup
logger.info("loading config")
with open(sys.argv[1], 'r') as f:
    config = json.load(f)

ENVIROMENT = config['api_enviroment']
DEVICE_UUID = UUID(hex=config['api_device_id'])
API_PASSWORD = config['api_password'] # password/auth token for the ubirch api

# password for encrypting the key store on the disk
KEYSTORE_PASSWORD = config.get("keystore_password",None)

logger.info(f'using endpoints at {ENVIROMENT}.ubirch.com')
logger.info(f'device ID is {DEVICE_UUID}')

AGGREGATE_INTERVAL = config['aggregate_interval']
SEAL_INTERVAL = config['seal_interval']

logger.info(f"aggregating every {AGGREGATE_INTERVAL} s and sealing every {SEAL_INTERVAL} s")

PATH_PERSISTENT_STORAGE = os.path.expanduser(config['persistent_storage_location']) # a path where the persistent data can be stored (queues, keys, last signatures, etc)

# set up path constants and global queues
PATH_MACHINEDATA_QUEUE = os.path.join(PATH_PERSISTENT_STORAGE, DEVICE_UUID.hex+"-machinedataqueue")
machinedata = persistqueue.Queue(PATH_MACHINEDATA_QUEUE) # stores incoming data messages from the machine

PATH_SEAL_QUEUE = os.path.join(PATH_PERSISTENT_STORAGE, DEVICE_UUID.hex+"-sealqueue")
seal_queue = persistqueue.Queue(PATH_SEAL_QUEUE) # stores aggregated data blocks for sealing

PATH_SEND_BLOCK_QUEUE = os.path.join(PATH_PERSISTENT_STORAGE, DEVICE_UUID.hex+"-sendblockqueue")
send_datablocks_queue = persistqueue.Queue(PATH_SEND_BLOCK_QUEUE) # stores data that has been sealed and anchored for transfer to customer backend

PATH_SENT_DATABLOCKS = os.path.join(PATH_PERSISTENT_STORAGE, DEVICE_UUID.hex+"-sentdatablocks") # path used to store the data arriving at the mock customer backend

# OPC-UA setup
opcua_client = None
if config["opcua_enabled"]:
    OPCUA_ADDRESS = config["opcua_address"]
    OPCUA_NAMESPACE = config["opcua_namespace"]
    OPCUA_NODES = config["opcua_nodes"]

    connected_ok = False
    while not connected_ok:
        try:
            opcua_client = opcua_connect(OPCUA_ADDRESS)
            opcua_subscribe(opcua_client, OPCUA_NAMESPACE,OPCUA_NODES)
            connected_ok = True
        except Exception as e:
            logger.error(f"could not connect/subscribe to OPC-UA: {repr(e)}")
            cooldown = 10
            logger.info(f"retrying connection in {cooldown} seconds...")
            time.sleep(cooldown)

# MQTT setup
mqtt_client = None
if config["mqtt_enabled"]:
    MQTT_ADDRESS = config["mqtt_address"]
    MQTT_PORT = config["mqtt_port"]
    MQTT_TOPICS = config["mqtt_topics"]
    MQTT_CLIENT_ID = config["mqtt_client_id"]
    MQTT_USERNAME = config.get("mqtt_username", None)
    MQTT_PASSWORD = config.get("mqtt_password", None)
    MQTT_TLS_ENABLED = config.get("mqtt_tls_enabled", False)

    connected_ok = False
    while not connected_ok:
        try:
            mqtt_client = mqtt_connect(MQTT_ADDRESS,MQTT_PORT,MQTT_CLIENT_ID, MQTT_TLS_ENABLED, MQTT_USERNAME,MQTT_PASSWORD)
            # (subscribing is handled in on_connect callback)
            connected_ok = True
        except Exception as e:
            logger.error(f"could not connect/subscribe to MQTT: {repr(e)}")
            cooldown = 10
            logger.info(f"retrying connection in {cooldown} seconds...")
            time.sleep(cooldown)

# set up keystore, ubirch protocol and ubirch api
# if password is not set, assume that this is attended boot and prompt for it
if KEYSTORE_PASSWORD == None or KEYSTORE_PASSWORD == "":
    time.sleep(0.5)
    KEYSTORE_PASSWORD = getpass.getpass("Please enter keystore password: ")
keystore = ubirch.KeyStore(os.path.join(PATH_PERSISTENT_STORAGE, "iiot-device.jks"), KEYSTORE_PASSWORD)

# create an instance of the protocol with signature saving
protocol = Proto(keystore, DEVICE_UUID,PATH_PERSISTENT_STORAGE)

# create an instance of the UBIRCH API and set the auth token
api = ubirch.API(env=ENVIROMENT)
api.set_authentication(DEVICE_UUID, API_PASSWORD)

logger.info("ubirch-protocol: checking key registration")
# register the public key at the UBIRCH key service if it is not already
if not api.is_identity_registered(DEVICE_UUID):
    certificate = keystore.get_certificate(DEVICE_UUID)
    key_registration = protocol.message_signed(DEVICE_UUID, UBIRCH_PROTOCOL_TYPE_REG, certificate)
    r = api.register_identity(bytes(key_registration))
    if r.status_code == codes.ok:
        logger.info("{}: public key registered".format(DEVICE_UUID))
    else:
        logger.error("{}: registration failed".format(DEVICE_UUID))
        sys.exit(1)
else:
    logger.info("{}: public key is already registered".format(DEVICE_UUID))

logger.info("starting main loop")
last_aggregate_data = time.time()
last_seal_blocks = time.time()

try:
    while True:
        # receiving MQTT and OPC-UA is handled in callbacks, so no related code here

        if time.time()-last_aggregate_data > AGGREGATE_INTERVAL: # time for aggregating received data into next block?        
            last_aggregate_data = time.time()
            aggregate_data(DEVICE_UUID,PATH_PERSISTENT_STORAGE)            

        if time.time()-last_seal_blocks > SEAL_INTERVAL: # time for sealing and anchoring the aggregated blocks?
            last_seal_blocks = time.time()
            seal_datablocks(protocol,api,DEVICE_UUID)            

        if not send_datablocks_queue.empty(): # data which was previously sealed and anchored for sending to customer backend available?
            send_datablocks(PATH_SENT_DATABLOCKS)
        
        time.sleep(0.0001)
except KeyboardInterrupt:
    pass
finally:
    logger.info("shutting down")
    if mqtt_client is not None:
        mqtt_client.disconnect()
    if opcua_client is not None:
        opcua_client.disconnect()        
