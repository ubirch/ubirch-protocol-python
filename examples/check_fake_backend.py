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

def get_UPP_from_BE(payload_hash:bytes,api: ubirch.API):
    """ Asks ubirch backend for a UPP with payload_hash. Returns UPP and prev. UPP data or None, None if not found. """
    response = api.verify(payload_hash,quick=False)
    if response.status_code == 200:
        try:
            upp_info = json.loads(response.content)
            #print(f"Received UPP info from verify endpoint:\n {upp_info}\n")            
            backend_upp = binascii.a2b_base64(upp_info['upp'])
            backend_prev_upp_base64 = upp_info['prev']
            if backend_prev_upp_base64 is not None:
                backend_prev_upp = binascii.a2b_base64(backend_prev_upp_base64)
            else:
                backend_prev_upp = None
            return backend_upp, backend_prev_upp

        except Exception as e:
            print(f"error while getting UPP: {repr(e)}")
            raise
    elif response.status_code == 404: #not found
        return None, None
    else:
        raise Exception(f"Error when checking if UPP exists. Response code: {response.status_code}, Response content: {repr(response.content)}")

def read_and_hash_data(datasets: list, data_folder: str):
    """ Reads all files in 'path' (sorted by name) and adds filename, hash, and parsed JSON data (dict) to dataset list. """
    
    _, _, filenames = next(walk(data_folder))
    filenames.sort()

    for filename in filenames:
        #print(filename)
        fullpath = path.join(data_folder,filename)
        #print(fullpath)

        with open(fullpath,'rb') as json_file:
            # read data
            block_raw = json_file.read()
            json_file.seek(0)
            block_dict = json.load(json_file)

            payload_hash = raw_hash(block_raw)

            # assemble dict and append
            entry = {
                "filename": filename,
                #"block_raw": block_raw, # we only need the hash and dict, so skip this
                "block_hash": payload_hash,
                "block_dict": block_dict,
                "results":{} # already add the dict for results of other checks
            }
            datasets.append(entry)

def get_all_UPPs(datasets: list, api: ubirch.API):
    """
    Iterates over 'datasets' and tries to get an UPP for each hash from the ubirch backend. Sets the check
    result of the entry depending on success or failure. In case of success adds the UPP and prev. UPP raw data to
    the dataset else adds 'None' as data.
    """
    total_upps = len(datasets)
    current_upp = 1
    not_found = 0
    for dataset in datasets:
        percent = int(current_upp/total_upps*100)
        print(f'\rChecking for UPP\t{current_upp}/{total_upps}\t{percent}%\tnot found: {not_found}          ',end="",flush=True)
        upp, prev_upp = get_UPP_from_BE(dataset["block_hash"], api)
        if upp is not None: # UPP found
            dataset["upp_raw"] = upp
            dataset["results"]["upp_found"] = True

            if prev_upp is not None: # check if prev UPP was found
                dataset["prev_upp_raw"] = prev_upp
                dataset["results"]["prev_upp_found"] = True
            else:
                dataset["prev_upp_raw"] = None
                dataset["results"]["prev_upp_found"] = False

        else: # no UPP found at all
            not_found +=1
            dataset["upp_raw"] = None
            dataset["results"]["upp_found"] = False
            dataset["prev_upp_raw"] = None
            dataset["results"]["prev_upp_found"] = False

        current_upp +=1
    print("")



#### Start Main Code ####
# Usage: python3 script.py folder stage
# Example: python3 ./examples/check_fake_backend.py '~/persist-ubirch-iiot-client/6fee257fdd72440686d85c7c8eb1c8eb-sentdatablocks' dev

ENVIROMENT = sys.argv[2] #ubirch api enviroment
print(f"Doing check on {ENVIROMENT} stage")

PATH= sys.argv[1] # folder with the customer backend data

api = ubirch.API(env=ENVIROMENT)

datasets = [] # list for holding all data and intermediate and final results

read_and_hash_data(datasets,PATH)
get_all_UPPs(datasets,api)


# some basic result printing
for dataset in datasets:
    # build indicators string from results
    indicators = ""
    results = dataset["results"]
    
    if results["upp_found"]:
        indicators += "--"
    else:
        indicators += "U!"

    if results["prev_upp_found"]:
        indicators += "---"
    else:
        indicators += "pU!"

    # print result line
    print(f'{dataset["filename"]}:\t{dataset["block_dict"]["block_nr"]}\t{indicators}')



# old stuff:
# fileindex = 1
# for filename in filenames:
#     #print(filename)
#     fullpath = path.join(PATH,filename)
#     #print(fullpath)

#     with open(fullpath,'rb') as json_file:
#         block_raw = json_file.read()
#         json_file.seek(0)
#         block = json.load(json_file)

#         payload_hash = base64_hash(block_raw)
#         blocknumber = block['block_nr']
#         indicators = ''
#         # check each item and append to check indicators
#         if fileindex != blocknumber:
#             indicators += 'B!'
#         else:
#             indicators += '--'

#         if get_UPP(raw_hash(block_raw), api) is None:
#             indicators += 'U!'
#         else:
#             indicators += '--'
        
#         print(f"{filename}:\t{blocknumber}\t{payload_hash}\t{indicators}")

#     fileindex += 1


