from os import walk,path
import json
import sys
import hashlib
import binascii
import ubirch

def raw_hash(raw_payload_data:bytes):
    # calculate SHA512 hash of message
    return hashlib.sha512(raw_payload_data).digest()

def base64_hash(raw_payload_data: bytes):   
    return binascii.b2a_base64(raw_hash(raw_payload_data),newline=False).decode()

def get_UPP(payload_hash:bytes,api: ubirch.API):
    response = api.verify(payload_hash,quick=False)
    if response.status_code == 200:
        try:
            upp_info = json.loads(response.content)
            #print(f"Received UPP info from verify endpoint: {upp_info}")
            backend_upp = binascii.a2b_base64(upp_info['upp'])
            return backend_upp

        except Exception as e:
            print(f"error while getting UPP: {repr(e)}")
            raise
    elif response.status_code == 404: #not found
        return None
    else:
        raise Exception(f"Error when checking if UPP exists. Response code: {response.status_code}, Response content: {repr(response.content)}")


ENVIROMENT = 'dev' #ubirch api enviroment

PATH= sys.argv[1]

api = ubirch.API(env=ENVIROMENT)

_, _, filenames = next(walk(PATH))
filenames.sort()

fileindex = 1
for filename in filenames:
    #print(filename)
    fullpath = path.join(PATH,filename)
    #print(fullpath)

    with open(fullpath,'rb') as json_file:
        block_raw = json_file.read()
        json_file.seek(0)
        block = json.load(json_file)

        payload_hash = base64_hash(block_raw)
        blocknumber = block['block_nr']
        indicators = ''
        # check each item and append to check indicators
        if fileindex != blocknumber:
            indicators += 'B!'
        else:
            indicators += '--'

        if get_UPP(raw_hash(block_raw), api) is None:
            indicators += 'U!'
        else:
            indicators += '--'
        
        print(f"{filename}:\t{blocknumber}\t{payload_hash}\t{indicators}")

    fileindex += 1


