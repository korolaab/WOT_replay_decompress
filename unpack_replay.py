from Crypto.Cipher import Blowfish
import json
import zlib
import argparse
import sys
Blowfish_KEY = 'DE 72 BE A0 DE 04 BE B1 DE FE BE EF DE AD BE EF'

def process_json_data(s):
    offset = 8 # start process json data with 8 byte
    json_data=[]
    for i in range(0,2):
        len_of_json_byte = s[offset:offset+4] #length of json_data bytes
        offset = offset + 4
        len_of_json = int.from_bytes(len_of_json_byte, byteorder='little') #length of json integer
        json_string = s[offset:offset+len_of_json].decode("utf-8") # save json data
        offset = offset+len_of_json
        json_data.append(json.loads(json_string)) #process json data
    return json_data,offset

def decrypt_xor(var, key):
    key = key[:len(var)]
    int_var = int.from_bytes(var, "big")
    int_key = int.from_bytes(key, "big")
    int_enc = int_var ^ int_key
    return int_enc.to_bytes(len(var), "big")
def Blowfish_decrypt(s):
    bs = Blowfish.block_size # 8 BYTEs
    key =  bytes.fromhex(Blowfish_KEY)
    ciphertext = s
    iv = ciphertext[:bs]    # first 8 bytes
    ciphertext = ciphertext[bs:] # the rest of data
    cipher = Blowfish.new(key, Blowfish.MODE_ECB) #blowfish cipher
    msg = bytearray(cipher.decrypt(iv)) #decrypt first 8 bytes
    last_block = msg #save first decrypted data

    for i in range(0,len(ciphertext),8):
        sub_str= cipher.decrypt(ciphertext[i:i+8]) #decrypt next 8 bytes
        last_block = decrypt_xor(last_block,sub_str) #xor with saved last decrypted 8 bytes
        msg.extend(last_block)
    return msg

def process_archive(s):
    decrypted_string = Blowfish_decrypt(s) #decrypt data
    return zlib.decompress(decrypted_string) #unpack data

def decompress(s):
    battle_info, offset =  process_json_data(s) #json_data is battle_info
    return battle_info ,process_archive(s[offset+8:])# battle_data

if __name__ == '__main__':
    if(len(sys.argv)<2):
        print("Input replay file")
        exit()
    replays = sys.argv[1:]
    for i in replays:
        print("decompressing "+ i)
        f = open(i,"rb")
        s = f.read()
        f.close()
        battle_json,battle_data = decompress(s)
        f = open(i+".json","w")
        f.write(str(battle_json))
        f.close()
        f = open(i+".raw","wb")
        f.write(battle_data)
        f.close()
