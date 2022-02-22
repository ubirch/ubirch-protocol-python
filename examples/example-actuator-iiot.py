import binascii
from hashlib import sha256
import hashlib
import json
import logging
import os
import pickle
import random
import sys
import time
import ed25519
from paho.mqtt import client as MqttClient
from uuid import UUID
from collections import deque
import base64
import serial

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
        global datablock_input_deque

        # handle payload string
        try:
            payload_string = msg.payload.decode(STRING_ENCODING)
        except UnicodeDecodeError:
            logger.error(f"undecodable message payload on topic {msg.topic}: {binascii.b2a_hex(msg.payload)}") 
            return
        logger.info(f"MQTT-receiver: received message from topic {msg.topic}")
        logger.debug("MQTT-receiver: payload: {payload_string}")
        datablock_input_deque.appendleft(payload_string) # append left so the processing is FIFO (left in, right out)
        global last_mqtt_receive #TODO: remove (timing debugging)
        last_mqtt_receive = time.time() #TODO: remove (timing debugging)
    
    for topic in topics:
        logger.info("MQTT-receiver: subscribing to topic {}".format(topic))
        client.subscribe(topic,qos=1) #set QOS depending on your network/needed reliability
    client.on_message = on_message
########################################################################

def get_UPP_from_BE(payload_hash: bytes, api: ubirch.API):
    """ Asks ubirch backend for a UPP with payload_hash. Returns UPP and prev. UPP data or None, None if not found. """
    response = api.verify(payload_hash, quick=True) # we need the quick verify endpoint here for timing reasons
    if response.status_code == 200:
        try:
            upp_info = json.loads(response.content)
            # print(f"Received UPP info from verify endpoint:\n {upp_info}\n")
            backend_upp = binascii.a2b_base64(upp_info.get('upp'))
            backend_prev_upp_base64 = upp_info.get('prev')
            if backend_prev_upp_base64 is not None:
                backend_prev_upp = binascii.a2b_base64(backend_prev_upp_base64)
            else:
                backend_prev_upp = None
            return backend_upp, backend_prev_upp

        except Exception as e:
            logger.error(f"error while getting UPP from backend: {repr(e)}")
            raise
    elif response.status_code == 404:  # not found
        return None, None
    else:
        raise Exception(f"Error when checking if UPP exists. Response code: {response.status_code}, Response content: {repr(response.content)}")

def verify_datablocks():
    """"
    Process all datablocks currently held in the queue
    """
    global datablock_input_deque
    global verified_datablocks_deque

    global last_verify_start #TODO: remove (debugging)
    last_verify_start = time.time() #TODO: remove (timing debugging)

    while len(datablock_input_deque) > 0:
        payload_string = datablock_input_deque.pop()
        payload_elements = payload_string.split(" ",1)
        if len(payload_elements) != 2:
            logger.error(f"unable to split payload into UPP and datablock, discarding payload: {payload_string}")
            continue # do next block
        try:
            upp = base64.b64decode(payload_elements[0], validate=True)
        except Exception as e:
            logger.error(f"unable to base64-decode UPP, discarding payload: {payload_string}")
            continue # do next block
        datablock = payload_elements[1]
        logger.debug("Processing datablock with:")
        logger.debug(f"UPP: {upp}")
        logger.debug(f"data: {datablock}")
        datablock_nr = json.loads(datablock)['block_nr'] #TODO remove timing debug
        # verify MQTT UPP with known nanoclient pubkey
        try:
            upp_unpacked = u_protocol.message_verify(upp)
        except Exception as e:
            logger.error(f"could not verify UPP: {repr(e)}")
            logger.error(f"discarding payload: {payload_string}")
            continue # process next datablock
        logger.debug("MQTT UPP verified OK")
        logger.debug(f"unpacked UPP:\n{upp_unpacked}")
        upp_payload_hash = upp_unpacked[-2]
        logger.debug(f"UPP payload hash is: {upp_payload_hash.hex()}")
        # calc block hash
        datablock_hash = hashlib.sha512(datablock.encode(STRING_ENCODING)).digest()
        logger.debug(f"datablock hash is: {datablock_hash.hex()}")        
        # verify hash with upp hash
        if datablock_hash != upp_payload_hash:
            logger.error(f"MQTT UPP hash does not match datablock hash")
            logger.error(f"discarding payload: {payload_string}")
            continue # do next block
        logger.debug("hashes of MQTT UPP and datablock match")
        # get backend UPP, wait for it if necessary
        save_datapoint("051_get_BE_UPP_start",datablock_nr,int(time.time()*1000)) #TODO remove timing debug
        polling_start = time.time()
        backend_upp = None
        while time.time()-polling_start < UPP_POLLING_TIMEOUT:
            try:
                backend_upp, _ = get_UPP_from_BE(datablock_hash,u_api)
            except Exception as e:
                logger.error(f"could not get UPP from backend: {repr(e)}")
                logger.error(f"will retry payload processing later")
                datablock_input_deque.append(payload_string) # put data back for retrying later
                return # abort processing for now
            
            if backend_upp != None:
                break # we got the UPP, exit loop
            logger.info("UPP is currently unknown at backend, will retry shortly...")
            time.sleep(UPP_POLLING_DELAY)
        if backend_upp == None: # we ran into the timeout or the UPP was not anchored at all
            logger.error(f"backend did not receive UPP (within timeout time)")
            logger.error(f"discarding payload: {payload_string}")
            continue # do next block
        save_datapoint("052_get_BE_UPP_end",datablock_nr,int(time.time()*1000))  #TODO remove timing debug
        logger.debug(f"received UPP from BE: {backend_upp}")
        logger.info(f"getting UPP from BE took {int((time.time()-polling_start)*1000)} ms") #TODO: remove (timing debugging)
        # compare UPPs
        if upp != backend_upp:
            logger.error(f"MQTT UPP does not match backend UPP")
            logger.error(f"discarding payload: {payload_string}")
            continue # do next block
        # put data into queue (left in to right out= FIFO)
        logger.debug("adding data to 'verified data' queue")
        verified_datablocks_deque.appendleft(datablock)
    
    global last_verify_end #TODO: remove (debugging)
    last_verify_end = time.time() #TODO: remove (timing debugging)

def act_on_data(data_topic : str, serial_port : str):
    """
    This is a simple example function acting depending on the verified data. It simply extracts
    the data from data_topic and acts accordingly and does not do more complex processing like
    structure or order checks or similar. A command to an actuator (calliope mini for demo purposes)
    is send via serial_port after the value is analyzed.
    """
    global verified_datablocks_deque
    while len(verified_datablocks_deque) > 0:
        data_str = verified_datablocks_deque.pop() # get verified data
        data_json = json.loads(data_str) # parse json
        messages = data_json['block_msgs']
        # simply find the first message in this block with the correct topic
        # and parse its data
        value = -1 # = not found
        for message in messages:
            if message['msg_type']== 'MQTTMessage':
                content = message['msg_content']
                if content['msg_topic'] == data_topic:
                    value = int(content['msg_payload'])
                    msg_queue_ts_ms = int(message['msg_queue_ts_ms']) #TODO: remove (timing debugging)

        logger.info(f"acting on new value from {data_topic}: {value}")
        # create command to send
        ## simply set a new random color for the LED:
        #r = random.randint(0,255) 
        #g = random.randint(0,255)
        #b = random.randint(0,255)
        # alternate LED color every 5 seconds (based on sent timestamp value):
        seconds = int(value/1000)
        if seconds%10 in range(0,5):
            r = 255
            g = 0
            b = 0
        else:
            r = 0
            g = 255
            b = 0

        actuator_command= f"{r}:{g}:{b}#".encode(STRING_ENCODING)
        
        logger.info(f"sending actuator command '{actuator_command}' via {serial_port}")
        ser = serial.Serial(serial_port, 115200, timeout=0.150)        
        ser.write(actuator_command)

        logger.info("saving debug timing statistics") # TODO remove this timing debug part:
        block_nr = data_json['block_nr']
        global last_mqtt_receive
        global last_verify_start
        global last_verify_end
        save_datapoint("000_time_ref",block_nr, value) # value in payload is the timestamp when sending
        save_datapoint("010_queued",block_nr, msg_queue_ts_ms)
        save_datapoint("020_aggregated",block_nr, data_json['block_ts_ms'])
        save_datapoint("030_seal_start",block_nr,data_json['seal_ts_ms'])
        save_datapoint("040_received",block_nr, int(last_mqtt_receive*1000))
        save_datapoint("050_verify_start",block_nr, int(last_verify_start*1000))
        save_datapoint("060_verify_end",block_nr, int(last_verify_end*1000))        
        
        save_datapoint("070_acting",block_nr, int(time.time()*1000)) # we are done with actuating here, save time

        

#TODO remove timing debug
# timing debug statistics helper function
def save_datapoint(data_name:str, measurement_ref: str, value):
    """"
    Loads a dict with measurements from a file, appends the new measurement, the saves the file again
    """
    filename = data_name+'.pckl'

    if os.path.isfile(filename):
        with open(filename, 'rb') as handle:
            dict = pickle.load(handle)
    else:
        dict = {}

    dict[measurement_ref] = value

    with open(filename, 'wb') as handle:
        pickle.dump(dict, handle)


        



#### start of main code section ###

#TODO: remove me, for debugging timing:
last_mqtt_receive = 0
last_verify_start = 0
last_verify_end = 0

# non-persistent queues for keeping received datablocks and UPPs in
# as well as the already verified data
datablock_input_deque = deque() # double ended queue
verified_datablocks_deque = deque()

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

STRING_ENCODING='utf-8'

UPP_POLLING_TIMEOUT = 5 # seconds, how long to wait for UPP to be verifable at backend when processing data block
UPP_POLLING_DELAY = 0.01  # seconds, how long to wait between UPP backend polling requests

ENVIRONMENT = config['api_environment']

NANOCLIENT_UUID = UUID(hex=config['nanoclient_uuid'])
NANOCLIENT_PUBKEY = ed25519.VerifyingKey(config['nanoclient_pubkey'], encoding='hex')


logger.info(f'using endpoints at {ENVIRONMENT}.ubirch.com')
logger.info(f'nanoclient UUID is {NANOCLIENT_UUID}')
pubkey_string = NANOCLIENT_PUBKEY.to_ascii(encoding='hex').decode(STRING_ENCODING)
logger.info(f'nanoclient public key is {pubkey_string}')

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
        if len(datablock_input_deque) > 0:
            logger.info(f"attempting to verify {len(datablock_input_deque)} datablocks")
            verify_datablocks()
        if len(verified_datablocks_deque) > 0:
            logger.info(f"attempting to act on {len(verified_datablocks_deque)} verified datablocks")
            act_on_data("ubirch/test/temperature","/dev/ttyACM0")

        time.sleep(0.0001)
except KeyboardInterrupt:
    pass
finally:
    logger.info("shutting down")
    if mqtt_client_receiving is not None:
        mqtt_client_receiving.disconnect()    
