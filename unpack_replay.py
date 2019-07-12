from Crypto.Cipher import Blowfish
from struct import pack
import re
import json
import zlib
import sys

Blowfish_KEY = 'DE 72 BE A0 DE 04 BE B1 DE FE BE EF DE AD BE EF'

def process_json_data(s):
    offset = 8
    json_data=[]
    for i in range(0,2):
        len_of_json_byte = s[offset:offset+4]
        offset = offset + 4
        len_of_json = int.from_bytes(len_of_json_byte, byteorder='little')
        json_string = s[offset:offset+len_of_json].decode("utf-8")
        offset = offset+len_of_json
        json_data.append(json.loads(json_string))
    return json_data,offset
def decrypt_xor(var, key):

    key = key[:len(var)]
    int_var = int.from_bytes(var, "big")
    int_key = int.from_bytes(key, "big")
    int_enc = int_var ^ int_key
    return int_enc.to_bytes(len(var), "big")
def xor(data, key):
    return bytearray(a^b for a, b in zip(*map(bytearray, [data, key])))
def Blowfish_decrypt(s):
    bs = Blowfish.block_size # 8 BYTEs
    key =  bytes.fromhex(Blowfish_KEY)
    ciphertext = s
    iv = ciphertext[:bs]    # first 8 bytes
    ciphertext = ciphertext[bs:] # the rest of data
    cipher = Blowfish.new(key, Blowfish.MODE_ECB) #blowfish cipher
    msg = bytearray(cipher.decrypt(iv))
    last_block = msg

    for i in range(0,len(ciphertext),8):
        sub_str= cipher.decrypt(ciphertext[i:i+8])
        last_block = decrypt_xor(last_block,sub_str)
        msg.extend(last_block)
    return msg

def process_archive(s):
    decrypted_string = Blowfish_decrypt(s)
    return decrypted_string

def decompress(s):
    battle_info, offset =  process_json_data(s) #json_data is battle_info
    return battle_info ,process_archive(s[offset+8:])# battle_data
