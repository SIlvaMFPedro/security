import os
import random
import string

from Crypto.Cipher import AES
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from Crypto.Util import Counter
from Crypto import Random

def encryptAES(key, input_text, iv):
    counter = Counter.new(128)
    aes = AES.new(key, AES.MODE_CTR, counter=counter, IV=iv)
    missing_data = 0
    output_encrypted = ''
    while True:
        chunk = input_text[:aes.block_size]
        input_text = input_text[aes.block_size:]
        if len(chunk) == 0:
            break
        elif len(chunk) % aes.block_size != 0:
            missing_data = 16 - len(chunk)
            chunk += chr(missing_data) * (aes.block_size - len(chunk) % aes.block_size)
        output_encrypted += aes.encrypt(chunk)
        if missing_data == 0:
            chunk = chr(255) * aes.block_size
            output_encrypted += aes.encrypt(chunk)

    return output_encrypted

def decryptAES(key, encrypted_text, iv):
    counter = Counter.new(128)
    aes = AES.new(key, AES.MODE_CTR, counter=counter, IV=iv)
    skip_lst = [chr(x) for x in range(1, aes.block_size)]
    output_decrypted = ''
    copy_input_text = encrypted_text
    while True:
        chunk = copy_input_text[:aes.block_size]
        copy_input_text = copy_input_text[aes.block_size:]
        if len(chunk) == 0:
            break
        output_decrypted += aes.decrypt(chunk)

    last = output_decrypted[-aes.block_size:]
    if last != (chr(255) * aes.block_size):
        if last[len(last) - 1] in skip_lst:
            idx = skip_lst.index(last[len(last) - 1]) + 1
            last = last[:-idx]
        final = output_decrypted[:-aes.block_size] + last
    else:
        final = output_decrypted[:-aes.block_size]
    return final

def generateIV():
    random_iv = Random.OSRNG.posix.new().read(AES.block_size)
    return random_iv

def derivate(key, salt, spec):
    length = 0
    if spec == 'ECDHE-AES128-SHA':
        length = 16
    elif spec == 'ECDHE-AES256-SHA':
        length = 32
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=b"hkdf-example", backend=default_backend())
    return hkdf.derive(key)

def serializePublicKey(key):
    return key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

def loadPublicKey(key):
    return serialization.load_pem_public_key(key, backend=default_backend())

def generateHashMsg(key, msg):
    hash = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    hash.update(msg)
    return hash.finalize()

def verifyHashMsg(key, msg, compare_hash):
    hash = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    hash.update(msg)
    return hash.verify(compare_hash)

def msg_generator(size=16, chars=string.ascii_uppercase + string.ascii_lowercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

