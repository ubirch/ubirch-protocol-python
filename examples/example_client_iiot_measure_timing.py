# this is a simple helper script to measure MQTT roundtrip times with the IIoT nanoclient example
# this code is partly based on 'MQTT Cookbook: Round-trip Time' https://linuxliberal.wordpress.com/2017/07/06/mqtt-cookbook-round-trip-time/
# this simply creates two clients, one which sends data (= sensor value) to the broker which is then used by 
# the nanoclient to create UPPs and publish them and the data to a data backend broker. The second client then reeceives the
# UPPs and datablock packets from the broker the nanoclient published to and measures the timing difference.


import paho.mqtt.client as mqtt
from time import time, sleep
import uuid
import sys
import json

SLEEP_INTERVAL = 0.05
DECIMAL_PLACES = 1

def on_connect_rcvr(client:mqtt.Client, userdata, flags, rc):
    client.subscribe(topic_rcvr,qos=config["mqtt_receive_qos"])

def on_message_rcvr(client, userdata, message):
    global in_flight
    global last_send_time

    rtt = time() - last_send_time # determine time it took
    in_flight = False    
  
    rtt_array.append(rtt)
    rtt_max = max(rtt_array)
    rtt_average = sum(rtt_array) / len(rtt_array)
    rtt_min = min(rtt_array)

    print("\nReceived:")
    print(message.payload.decode('utf-8'))    
    print(f'send: QOS={config["mqtt_send_qos"]}, TLS={config["mqtt_send_tls_enabled"]}')
    print(f'receive: QOS={config["mqtt_receive_qos"]}, TLS={config["mqtt_receive_tls_enabled"]}') 
    print('Messages total: %s' % len(rtt_array))
    print('Last [ms]: %s' % round(rtt*1000,DECIMAL_PLACES))
    print('Max [ms]: %s' % round(rtt_max*1000,DECIMAL_PLACES))
    print('Avg [ms]: %s' % round(rtt_average*1000,DECIMAL_PLACES))
    print('Min [ms]: %s' % round(rtt_min*1000,DECIMAL_PLACES))

# load config file from first argument
with open(sys.argv[1], 'r') as f:
    config = json.load(f)

rtt_array = []

#receiver
topic_rcvr = config["mqtt_receive_topic"]
client_rcvr = mqtt.Client()
client_rcvr.on_connect = on_connect_rcvr
client_rcvr.on_message = on_message_rcvr
if config["mqtt_receive_tls_enabled"]:
    client_rcvr.tls_set()
client_rcvr.username_pw_set(config["mqtt_receive_username"], config["mqtt_receive_password"])
client_rcvr.connect(config["mqtt_receive_address"],config["mqtt_receive_port"])

#sender
topic_sndr = config["mqtt_send_topic"]
client_sndr = mqtt.Client()
if config["mqtt_send_tls_enabled"]:
    client_sndr.tls_set()
client_sndr.username_pw_set(config["mqtt_send_username"], config["mqtt_send_password"])
client_sndr.connect(config["mqtt_send_address"],config["mqtt_send_port"])

in_flight = False
last_send_time = 0

while True:
    last_send_time = time() # remember publish time in global
    client_sndr.publish(topic_sndr, "some test data", qos=config["mqtt_send_qos"]) # send the data
    in_flight = True
    while in_flight == True:
        client_sndr.loop()
        client_rcvr.loop() # evaluation of timing is done in receive callback, which resets in flight flag too
    sleep(SLEEP_INTERVAL)
    