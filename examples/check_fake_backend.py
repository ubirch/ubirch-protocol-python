from os import walk,path
import json
import sys
import hashlib
import binascii
import uuid
import ed25519
import ubirch

class VerifyProto(ubirch.Protocol):
    """
    Implements the ubirch-protocol for verifying only.
    """

    # public keys and UUIDs of the ubirch backend for verification of responses
    UUID_DEV = uuid.UUID(hex="9d3c78ff-22f3-4441-a5d1-85c636d486ff")
    PUB_DEV = ed25519.VerifyingKey("a2403b92bc9add365b3cd12ff120d020647f84ea6983f98bc4c87e0f4be8cd66", encoding='hex')
    UUID_DEMO = uuid.UUID(hex="07104235-1892-4020-9042-00003c94b60b")
    PUB_DEMO = ed25519.VerifyingKey("39ff77632b034d0eba6d219c2ff192e9f24916c9a02672acb49fd05118aad251", encoding='hex')
    UUID_PROD = uuid.UUID(hex="10b2e1a4-56b3-4fff-9ada-cc8c20f93016")
    PUB_PROD = ed25519.VerifyingKey("ef8048ad06c0285af0177009381830c46cec025d01d86085e75a4f0041c2e690", encoding='hex')

    def __init__(self, key_store: ubirch.KeyStore, uuid: uuid.UUID, device_pubkey: ed25519.VerifyingKey) -> None:
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

    def _sign(self, uuid: uuid.UUID, message: bytes) -> bytes:        
        raise NotImplementedError

    def _verify(self, uuid: uuid.UUID, message: bytes, signature: bytes):
        return self.__ks.find_verifying_key(uuid).verify(signature, message)

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

def verify_UPP_signatures(datasets: list, proto: VerifyProto):
    """ Checks the signatures of all UPPs and prev. UPPs in datasets and if OK unpacks them into datasets. Also updates results accordingly. """
    for dataset in datasets:
        upp_raw = dataset["upp_raw"]
        prev_upp_raw = dataset["prev_upp_raw"]

        # check for UPP
        upp_unpacked = None
        dataset["results"]["upp_sig_ok"] = None # None = 'not tested'
        if upp_raw is not None:
            try:
                upp_unpacked = proto.message_verify(upp_raw)
                dataset["results"]["upp_sig_ok"] = True
            except ed25519.BadSignatureError:
                #print("Bad UPP signature check")                
                dataset["results"]["upp_sig_ok"] = False
        dataset["unpacked_upp"] = upp_unpacked

        # check for prev UPP
        prev_upp_unpacked = None
        dataset["results"]["prev_upp_sig_ok"] = None # None = 'not tested'
        if prev_upp_raw is not None:
            try:
                prev_upp_unpacked = proto.message_verify(prev_upp_raw)
                dataset["results"]["prev_upp_sig_ok"] = True
            except ed25519.BadSignatureError:
                #print("Bad prev UPP signature check")                
                dataset["results"]["prev_upp_sig_ok"] = False
        dataset["unpacked_prev_upp"] = prev_upp_unpacked

def check_block_numbers(datasets: list, first_block=1):
    """ Check the block numbers of all datasets for consistency. First_block is the number the first blok should have. Expects data to be sorted by block numbers. """
    last_block_nr = first_block -1
    for dataset in datasets:
                
        block_nr = dataset["block_dict"]["block_nr"]

        if (block_nr-1) == last_block_nr:
            #print("Block Nr OK")
            dataset["results"]["block_nr_ok"] = True
        else:
            #print("Block Nr NOT OK")
            dataset["results"]["block_nr_ok"] = False

        last_block_nr = block_nr


#### Start Main Code ####
# Usage: python3 script.py folder stage
# Example: python3 ./examples/check_fake_backend.py '~/persist-ubirch-iiot-client/6fee257fdd72440686d85c7c8eb1c8eb-sentdatablocks' dev

ENVIROMENT = sys.argv[2] #ubirch api enviroment
print(f"Doing check on {ENVIROMENT} stage")

PATH= sys.argv[1] # folder with the customer backend data

# data of device that anchored the data
myuuid = uuid.UUID(hex="714f93a92aee448da77f9b5ac0c905a4")
mypubkey = ed25519.VerifyingKey("ebdf58aae7d229c3df891a00dc95d8a63ec966f28813ef9bef57bdfb253ddd72", encoding='hex')

u_api = ubirch.API(env=ENVIROMENT)
u_keystore = ubirch.KeyStore("temporary_keystore.jks","notsecret")
u_protocol = VerifyProto(u_keystore,myuuid, mypubkey)

datasets = [] # list for holding all data and intermediate and final results

read_and_hash_data(datasets,PATH)
get_all_UPPs(datasets,u_api)

# #REMOVE ME: alter UPP for testing signature check
# cut=-32
# datasets[4]["upp_raw"] = datasets[4]["upp_raw"][:cut]+ b'\x42' + datasets[4]["upp_raw"][(cut-1):]
# datasets[7]["prev_upp_raw"] = datasets[4]["prev_upp_raw"][:cut]+ b'\x42' + datasets[4]["prev_upp_raw"][(cut-1):]

print("Verifying signatures...")
verify_UPP_signatures(datasets, u_protocol)

first_block_nr = 152
check_block_numbers(datasets,first_block_nr)


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

    if results["upp_sig_ok"] == True:
        indicators += "---"
    elif results["upp_sig_ok"] == False:
        indicators += "Us!"
    else: # 'None' = not tested
        indicators += "Us?"
    
    if results["prev_upp_sig_ok"] == True:
        indicators += "----"
    elif results["prev_upp_sig_ok"] == False:
        indicators += "pUs!"
    else: # 'None' = not tested
        indicators += "pUs?"

    if results["block_nr_ok"]:
        indicators += "---"
    else:
        indicators += "bn!"

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


