# Written By Ananke: https://github.com/4n4nk3

import json
# pycryptodome
from Crypto.Cipher import AES
from base64 import b64encode, b64decode

def encode_aes(text_input: str) -> str:
    """Encode a string and output an json in string form.\n"""
    secret = b'4n4nk353hlli5w311d0n3andI1ik3it!'
    cipher = AES.new(secret, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(bytes(text_input, 'utf-8'))
    lista = [ciphertext, tag, cipher.nonce]
    json_k = ['ciphertext', 'tag', 'nonce']
    json_v = [b64encode(x).decode('utf-8') for x in lista]
    return json.dumps(dict(zip(json_k, json_v)))


def decode_aes(json_input: str) -> str:
    """Decode a string in json form and output a string.\n"""
    try:
        b64 = json.loads(json_input)
        json_k = ['ciphertext', 'tag', 'nonce']
        jv = {k: b64decode(b64[k]) for k in json_k}
        secret = b'4n4nk353hlli5w311d0n3andI1ik3it!'
        cipher = AES.new(secret, AES.MODE_EAX, nonce=jv['nonce'])
        cleared = (cipher.decrypt_and_verify(jv['ciphertext'], jv['tag'])).decode('utf-8')
        return cleared
    except Exception as exception_decode:
        print(exception_decode)
        print("Incorrect decryption")